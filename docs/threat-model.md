# Threat model — OSINT Orchestrator (OWASP pytm, threat library 114 threats)

Modular monolith (ADR-001): one FastAPI process with an in-process APScheduler and a SQLite store drives OSINT collectors, qualifies evidence with an LLM, normalises findings to STIX 2.1 (ADR-002), ingests them into OpenCTI (ADR-003/008), seals a signed report chain per run (ADR-007) and dispatches alerts by webhook and e-mail. Access uses static API keys and a single instance (ADR-005), with an optional OIDC proxy perimeter (ADR-006) and an external STIX intake (ADR-011). Operator prose is Spanish, code English (ADR-004).

## Assumptions

- Single-instance deployment on a trusted Docker host; loopback-published ports are reachable only from that host.
- The Docker host and the compose network are operated by the same team as the orchestrator.
- ORCHESTRATOR_API_KEY is set. require_api_key is a no-op with an empty key (open mode, documented in ADR-005 and ADR-006); that mode is out of this model's scope.
- The shipped docker-compose.auth.yml terminates no TLS: oauth2-proxy listens on plain HTTP on loopback and hardcodes OAUTH2_PROXY_COOKIE_SECURE=false. A TLS terminator in front of it is a production hardening step, modelled as absent.
- Alert channels are modelled with their defaults: SMTP with STARTTLS (ALERT_SMTP_STARTTLS=true) and the webhook over the operator's URL with the optional HMAC signature (ALERT_WEBHOOK_SECRET) unset.
- Collectors only query targets authorised in targets.yaml (operator attestation per target).
- OpenCTI, MISP, Amass, SocialOSINT and the OIDC overlay are optional deployments; the model covers them when enabled.
- ORCHESTRATOR_SECRET_KEY is a private, randomly generated value. The default insecure-dev-key only earns a startup warning (auth.py); with it, or with an empty key, anyone can forge a manifest, and the integrity claims of this model do not hold.
- LLM_BASE_URL points at the Ollama service of the shipped compose (same host, compose network). OllamaClient posts to whatever URL is configured (providers/ollama.py), so a remote LLM_BASE_URL turns `llm: local` into the cloud-provider case of this model; a remote Ollama is not modelled separately.

## Element classes

A response is written per class: the same threat means something different on the orchestrator, on an unauthenticated sidecar, on a vendor service, on a store or on a flow.

- **orchestrator**: Orchestrator API (FastAPI + APScheduler), APScheduler cron jobs
- **sidecar**: SpiderFoot, Amass v5 engine, SocialOSINT sidecar, Ollama (local models), Ollama HTTP API
- **vendor**: Tavily search API, Cloud LLM provider, SocialOSINT's LLM endpoint, SMTP relay (alert e-mail), Alert webhook receiver, oauth2-proxy, Keycloak, MISP, OpenCTI platform, OpenCTI backing stores, connector-misp
- **store**: SQLite run store, targets.yaml, daily_reports (sealed runs), Amass asset database (shared volume), SocialOSINT cache volume
- **flow**: every dataflow, named by what it carries

## Findings: 758 across 88 distinct threats

Every finding carries a triage response:

- **accepted**: 438 finding(s)
- **mitigated**: 21 finding(s)
- **transferred**: 299 finding(s)

## Triage summary by threat and element class

| Threat | Severity | Class | Response | Rationale |
| --- | --- | --- | --- | --- |
| AA01 Authentication Abuse/ByPass | Medium | orchestrator | mitigated | Every data route depends on require_api_key (401 asserted by tests) under the assumption that ORCHESTRATOR_API_KEY is set; /health and /metrics are intentionally open; the console shell carries no data (ADR-010). |
| AA01 Authentication Abuse/ByPass | Medium | sidecar | accepted | SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services. |
| AA01 Authentication Abuse/ByPass | Medium | vendor | transferred | Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's. |
| AA02 Principal Spoof | Medium | orchestrator | mitigated | Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds an authenticated person (ADR-006). |
| AA02 Principal Spoof | Medium | sidecar | accepted | The sidecars accept anything on the compose network as the orchestrator (AA01). |
| AA02 Principal Spoof | Medium | vendor | transferred | Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's. |
| AA03 Exploitation of Trusted Credentials | High | sidecar | accepted | SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services. |
| AA03 Exploitation of Trusted Credentials | High | vendor | accepted | Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation. |
| AA04 Exploiting Trust in Client | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| AA04 Exploiting Trust in Client | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| AC01 Privilege Abuse | Medium | sidecar | accepted | No roles on the sidecars: every caller can do everything they do (AA01). |
| AC01 Privilege Abuse | Medium | store | accepted | One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, the SocialOSINT sidecar for its cache); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible. |
| AC01 Privilege Abuse | Medium | vendor | transferred | Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's. |
| AC02 Shared Data Manipulation | Medium | store | accepted | The Amass asset database is shared between the engine and the orchestrator on one volume of the trusted host (ADR-005); oam_subs output is parsed as untrusted text. |
| AC02 Shared Data Manipulation | Medium | vendor | transferred | OpenCTI's backing stores (Elasticsearch, MinIO, RabbitMQ, Redis) are owned and hardened by the OpenCTI platform deployment. |
| AC05 Content Spoofing | Medium | flow | accepted | Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
| AC06 Using Malicious Files | Very High | sidecar | accepted | The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars. |
| AC06 Using Malicious Files | Very High | vendor | transferred | Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve. |
| AC07 Exploiting Incorrectly Configured Access Control Security Levels | Medium | sidecar | accepted | There is no access control to misconfigure on the sidecars (AA01). |
| AC07 Exploiting Incorrectly Configured Access Control Security Levels | Medium | vendor | transferred | Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's. |
| AC08 Manipulate Registry Information | Medium | sidecar | accepted | Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host. |
| AC08 Manipulate Registry Information | Medium | vendor | accepted | Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host. |
| AC09 Functionality Misuse | Medium | sidecar | accepted | Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules. |
| AC09 Functionality Misuse | Medium | vendor | transferred | Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's. |
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
| AC23 Credentials Disclosure | High | flow | accepted | Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI. |
| API01 Exploit Test APIs | High | orchestrator | mitigated | No test or debug endpoints ship; /docs is the read-only OpenAPI UI and every data route behind it still requires the API key (tests assert 401 without it). |
| CR01 Session Sidejacking | High | flow | accepted | The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback and hardcodes OAUTH2_PROXY_COOKIE_SECURE=false (no variable reads it): the session cookie is exposed to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front of the proxy and a Compose override that sets OAUTH2_PROXY_COOKIE_SECURE to true. |
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
| DE04 Audit Log Manipulation | High | store | accepted | Run rows are outside the manifest chain: /targets/{id}/chain/verify checks the manifest hash, signature, chain link and artefact files (evidence.py), not a row's status, collectors or timestamps, so an edit to those fields with the manifest intact goes undetected. Hardening: database file permissions, backups and disk encryption. |
| DE04 Audit Log Manipulation | High | store | accepted | The cache is outside the manifest chain: profiles and posts under /app/data are plain files the sidecar rewrites at will, with no signature or audit log, and the orchestrator only ever reads the sidecar's report, so an edit there is invisible to it. Hardening: an ephemeral or read-only volume and file permissions. |
| DE04 Audit Log Manipulation | High | store | mitigated | Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper. |
| DE04 Audit Log Manipulation | High | vendor | transferred | OpenCTI's own audit trail lives in its backing stores and is the platform's. |
| DO01 Flooding | Medium | orchestrator | accepted | No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator. |
| DO01 Flooding | Medium | sidecar | accepted | The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps. |
| DO01 Flooding | Medium | vendor | transferred | Rate limiting of vendor services is the vendor's. |
| DO02 Excessive Allocation | Medium | orchestrator | accepted | Per-run budgets cap the collectors and the models (TAVILY_MAX_CALLS_PER_RUN, LLM_QUALIFY_MAX_ITEMS, LLM_MAX_TOKENS), but POST /bundles reads the whole body with request.json() before validating it and no middleware caps uploads, so an authenticated producer can exhaust memory with one request. Hardening: a body-size limit at the reverse proxy or TLS terminator in front of :8000. |
| DO02 Excessive Allocation | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DO02 Excessive Allocation | Medium | store | accepted | No retention reaches this volume: the sidecar's CacheManager keeps profiles and posts under /app/data until the operator removes the volume or prunes it, and deleting a session removes only the session file. The orchestrator keeps nothing of it beyond the unverified note. Hardening: an ephemeral (tmpfs) volume or a purge job for /app/data, sized to the retention the operator owes the people in those profiles. |
| DO02 Excessive Allocation | Medium | store | accepted | Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes. |
| DO02 Excessive Allocation | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DR01 Unprotected Sensitive Data | High | flow | accepted | Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
| DS01 Excavation | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DS01 Excavation | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DS03 Footprinting | Very Low | sidecar | accepted | Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments. |
| DS03 Footprinting | Very Low | vendor | transferred | Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment. |
| DS04 XSS Targeting Error Pages | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DS04 XSS Targeting Error Pages | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DS06 Data Leak | Very High | flow | accepted | Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000/:8002. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
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

### Severity: Very High (75)

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

#### F-174 — Overflow Buffers  `INP02`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS) and LLM_MAX_OBSERVABLES_IN_PROMPT.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-182 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — The pipeline isolates every step (collect, qualify, normalise, synthesise, seal, alert): a raised error fails the run, never a privileged transaction; the process runs as uid 1000 with no setuid paths (Dockerfile).
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-185 — Cross Site Request Forgery  `AC21`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no ambient credential to forge cross-site; the console CSP sets form-action 'none'; the scheduler has no HTTP surface. The OIDC overlay adds oauth2-proxy's CSRF token.
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-186 — Overflow Buffers  `INP02`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS) and LLM_MAX_OBSERVABLES_IN_PROMPT.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-195 — Cross Site Request Forgery  `AC21`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no ambient credential to forge cross-site; the console CSP sets form-action 'none'; the scheduler has no HTTP surface. The OIDC overlay adds oauth2-proxy's CSRF token.
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-215 — Command Line Execution through SQL Injection  `INP05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-221 — Path Traversal  `HA01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-230 — Using Malicious Files  `AC06`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-232 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-257 — Session Hijacking - ServerSide  `AC17`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-260 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-266 — Path Traversal  `HA01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-275 — Using Malicious Files  `AC06`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-277 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-302 — Session Hijacking - ServerSide  `AC17`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-305 — Command Line Execution through SQL Injection  `INP05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-311 — Path Traversal  `HA01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-320 — Using Malicious Files  `AC06`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-322 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-347 — Session Hijacking - ServerSide  `AC17`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-354 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-360 — Path Traversal  `HA01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-369 — Using Malicious Files  `AC06`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-371 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-396 — Session Hijacking - ServerSide  `AC17`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-401 — Command Line Execution through SQL Injection  `INP05`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-406 — Path Traversal  `HA01`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-415 — Using Malicious Files  `AC06`

- **Element:** MISP (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-417 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-441 — Session Hijacking - ServerSide  `AC17`

- **Element:** MISP (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-445 — Cross Site Tracing  `CR02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — TRACE handling at Keycloak and OpenCTI is the vendor image's; both sit on the compose network or loopback (ADR-005) and nothing the orchestrator serves issues TRACE. Hardening: a TLS terminator in front of them that drops TRACE.
- **pytm mitigations:** Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.

#### F-446 — Command Line Execution through SQL Injection  `INP05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-452 — Path Traversal  `HA01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-460 — Using Malicious Files  `AC06`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-462 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-486 — Session Hijacking - ServerSide  `AC17`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-493 — Overflow Buffers  `INP02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-497 — Buffer Manipulation  `INP07`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** To help protect an application from buffer manipulation attacks, a number of potential mitigations can be leveraged. Before starting the development of the application, consider using a code language (e.g., Java) or compiler that limits the ability of developers to act beyond the bounds of a buffer. If the chosen language is susceptible to buffer related issues (e.g., C) then consider using secure functions instead of those vulnerable to buffer manipulations. If a potentially dangerous function must be used, make sure that proper boundary checking is performed. Additionally, there are often a number of compiler-based mechanisms (e.g., StackGuard, ProPolice and the Microsoft Visual Studio /GS flag) that can help identify and protect against potential buffer issues. Finally, there may be operating system level preventative functionality that can be applied.

#### F-507 — File Content Injection  `INP23`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Validate all input for content including files. Ensure that if files and remote content must be accepted that once accepted, they are placed in a sandbox type location so that lower assurance clients cannot write up to higher assurance processes (like Web server processes for example)Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.Implementation: Virus scanning on hostImplementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.

#### F-510 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-523 — Session Hijacking - ClientSide  `AC18`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-526 — Cross Site Request Forgery  `AC21`

- **Element:** connector-misp (vendor)
- **Response:** transferred — connector-misp has no browser-facing surface; CSRF on vendor UIs is the vendor's (oauth2-proxy implements its own CSRF token).
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-528 — Cross Site Tracing  `CR02`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — FastAPI answers TRACE with 405 and the console ships no inline script that could read reflected headers; the plaintext proxied hop itself is the DS06 decision (shipped overlay without TLS). Hardening: TLS terminator that drops TRACE.
- **pytm mitigations:** Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.

#### F-534 — Data Leak  `DS06`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000/:8002. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-538 — Cross Site Tracing  `CR02`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — FastAPI answers TRACE with 405 and the console ships no inline script that could read reflected headers; the plaintext proxied hop itself is the DS06 decision (shipped overlay without TLS). Hardening: TLS terminator that drops TRACE.
- **pytm mitigations:** Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.

#### F-558 — Data Leak  `DS06`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000/:8002. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-566 — Data Leak  `DS06`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000/:8002. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-579 — Data Leak  `DS06`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000/:8002. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-611 — Data Leak  `DS06`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000/:8002. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-618 — Data Leak  `DS06`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000/:8002. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-657 — Data Leak  `DS06`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000/:8002. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-663 — Data Leak  `DS06`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000/:8002. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-669 — Data Leak  `DS06`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000/:8002. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-675 — Data Leak  `DS06`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Handling limits are declared per endpoint (SECRET where a service receives its own credentials, PUBLIC for the open web and anonymous callers) and per flow (SECRET on the trusted host or under TLS, PUBLIC in clear across the internet boundary), so what fires here is deliberate: every lookup tells the public source which name is being researched (search queries and discovery traffic, plaintext DNS/WHOIS included; Amass's provider keys go to the providers that issued them, over TLS), and the operator's API key, OIDC session and Keycloak password cross the host boundary in clear on :8000 and on the shipped OIDC overlay, which terminates no TLS (ADR-005). The disclosure to the sources queried is inherent to OSINT and bounded by the per-target authorisation. Hardening: a TLS terminator in front of :8000/:8002. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

### Severity: High (283)

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

#### F-176 — Exploit Test APIs  `API01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — No test or debug endpoints ship; /docs is the read-only OpenAPI UI and every data route behind it still requires the API key (tests assert 401 without it).
- **pytm mitigations:** Ensure that production systems to not contain sample or test APIs and that these APIs are only used in development environments.

#### F-180 — Privilege Escalation  `AC12`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-183 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-184 — Schema Poisoning  `AC15`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-191 — Privilege Escalation  `AC12`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-193 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-194 — Schema Poisoning  `AC15`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-199 — Audit Log Manipulation  `DE04`

- **Element:** SQLite run store (store)
- **Response:** accepted — Run rows are outside the manifest chain: /targets/{id}/chain/verify checks the manifest hash, signature, chain link and artefact files (evidence.py), not a row's status, collectors or timestamps, so an edit to those fields with the manifest intact goes undetected. Hardening: database file permissions, backups and disk encryption.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-203 — Audit Log Manipulation  `DE04`

- **Element:** targets.yaml (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-207 — Audit Log Manipulation  `DE04`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-212 — Audit Log Manipulation  `DE04`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-213 — Server Side Include (SSI) Injection  `INP03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-214 — HTTP Request Splitting  `INP04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-223 — Format String Injection  `INP08`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-224 — LDAP Injection  `INP09`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-226 — Relative Path Traversal  `INP11`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-228 — Dictionary-based Password Attack  `CR03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-234 — Embedding Scripts within Scripts  `SC03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-235 — PHP Remote File Inclusion  `INP16`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-238 — XSS Using Alternate Syntax  `SC04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-241 — Removing Important Client Functionality  `SC05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-243 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-246 — Exploiting Trust in Client  `AA04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-250 — XML Attribute Blowup  `INP22`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-251 — XSS Targeting URI Placeholders  `INP28`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-253 — SOAP Array Overflow  `INP34`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-255 — HTTP Request Smuggling  `INP37`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-256 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-258 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-259 — HTTP Request Splitting  `INP04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-268 — Format String Injection  `INP08`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-269 — LDAP Injection  `INP09`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-271 — Relative Path Traversal  `INP11`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-273 — Dictionary-based Password Attack  `CR03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-279 — Embedding Scripts within Scripts  `SC03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-280 — PHP Remote File Inclusion  `INP16`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-283 — XSS Using Alternate Syntax  `SC04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-286 — Removing Important Client Functionality  `SC05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-288 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-291 — Exploiting Trust in Client  `AA04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-295 — XML Attribute Blowup  `INP22`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-296 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-298 — SOAP Array Overflow  `INP34`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-300 — HTTP Request Smuggling  `INP37`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-301 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-303 — Server Side Include (SSI) Injection  `INP03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-304 — HTTP Request Splitting  `INP04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-313 — Format String Injection  `INP08`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-314 — LDAP Injection  `INP09`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-316 — Relative Path Traversal  `INP11`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-318 — Dictionary-based Password Attack  `CR03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-324 — Embedding Scripts within Scripts  `SC03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-325 — PHP Remote File Inclusion  `INP16`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-328 — XSS Using Alternate Syntax  `SC04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-331 — Removing Important Client Functionality  `SC05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-333 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-336 — Exploiting Trust in Client  `AA04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-340 — XML Attribute Blowup  `INP22`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-341 — XSS Targeting URI Placeholders  `INP28`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-343 — SOAP Array Overflow  `INP34`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-345 — HTTP Request Smuggling  `INP37`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-346 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-351 — Audit Log Manipulation  `DE04`

- **Element:** SocialOSINT cache volume (store)
- **Response:** accepted — The cache is outside the manifest chain: profiles and posts under /app/data are plain files the sidecar rewrites at will, with no signature or audit log, and the orchestrator only ever reads the sidecar's report, so an edit there is invisible to it. Hardening: an ephemeral or read-only volume and file permissions.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-352 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-353 — HTTP Request Splitting  `INP04`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-362 — Format String Injection  `INP08`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-363 — LDAP Injection  `INP09`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-365 — Relative Path Traversal  `INP11`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-367 — Dictionary-based Password Attack  `CR03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-373 — Embedding Scripts within Scripts  `SC03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-374 — PHP Remote File Inclusion  `INP16`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-377 — XSS Using Alternate Syntax  `SC04`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-380 — Removing Important Client Functionality  `SC05`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-382 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-385 — Exploiting Trust in Client  `AA04`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-389 — XML Attribute Blowup  `INP22`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-390 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-392 — SOAP Array Overflow  `INP34`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-394 — HTTP Request Smuggling  `INP37`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-395 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-397 — Direct Prompt Injection  `LLM01`

- **Element:** Ollama (local models) (sidecar)
- **Response:** accepted — Collected text reaches the model delimited and flattened, replies are JSON-schema validated, and the model has no tools, so an injected instruction cannot execute anything. It can still skew the assessment: a schema-valid risk level feeds alert_case_reason (pipeline.py, alerts/__init__.py) and can raise or suppress a risk-threshold alert. Residual risk accepted: the new-observables rule fires independently of the model, the evidence and rationale stay visible to the analyst, and model output is an aid, not a determination (README, Responsible use).
- **pytm mitigations:** Implement input content filtering and guardrails. Use prompt engineering techniques to make the system prompt more robust against injection. Apply output validation to detect and block manipulated responses. Monitor and log prompts for anomalous patterns.

#### F-398 — Jailbreaking and Safety Bypass  `LLM07`

- **Element:** Ollama (local models) (sidecar)
- **Response:** accepted — Same as LLM01: a jailbroken reply is either rejected by the schema or lands as a plausible-looking but wrong assessment that an analyst must review; it drives no action beyond the alert-threshold comparison.
- **pytm mitigations:** Implement layered defense with both system prompts and content filtering. Use output filtering to detect and block policy-violating responses. Regularly test with adversarial prompts and update defenses. Consider using classifier models to detect jailbreaking attempts.

#### F-399 — Sensitive Information Disclosure Through Output  `LLM08`

- **Element:** Ollama (local models) (sidecar)
- **Response:** accepted — A reply is consumed as data, never executed: the orchestrator's synthesis is JSON-schema validated and SocialOSINT's report is attached as an unverified note, and both are stored and rendered escaped under the console's CSP. What a reply can echo is the public footprint the prompt carried, which the evidence already holds; nothing filters personal-data patterns out of a summary before it is stored. Hardening: output redaction or DLP before a finding or note is persisted.
- **pytm mitigations:** Implement output filtering to detect and redact sensitive data patterns (PII, credentials, etc.). Use output encoding appropriate to the consumption context. Apply data loss prevention (DLP) controls on LLM outputs. Minimize the amount of sensitive data in the LLM's context.

#### F-400 — Server Side Include (SSI) Injection  `INP03`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-408 — Format String Injection  `INP08`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-409 — LDAP Injection  `INP09`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-411 — Relative Path Traversal  `INP11`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-413 — Dictionary-based Password Attack  `CR03`

- **Element:** MISP (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-419 — Embedding Scripts within Scripts  `SC03`

- **Element:** MISP (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-420 — PHP Remote File Inclusion  `INP16`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-422 — XSS Using Alternate Syntax  `SC04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-425 — Removing Important Client Functionality  `SC05`

- **Element:** MISP (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-427 — Exploitation of Trusted Credentials  `AA03`

- **Element:** MISP (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-430 — Exploiting Trust in Client  `AA04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-434 — XML Attribute Blowup  `INP22`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-435 — XSS Targeting URI Placeholders  `INP28`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-437 — SOAP Array Overflow  `INP34`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-439 — HTTP Request Smuggling  `INP37`

- **Element:** MISP (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-440 — Session Credential Falsification through Prediction  `AC16`

- **Element:** MISP (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-442 — Server Side Include (SSI) Injection  `INP03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-443 — Session Sidejacking  `CR01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-444 — HTTP Request Splitting  `INP04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.

#### F-454 — Format String Injection  `INP08`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-455 — LDAP Injection  `INP09`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-457 — Relative Path Traversal  `INP11`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-463 — Embedding Scripts within Scripts  `SC03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-464 — PHP Remote File Inclusion  `INP16`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-468 — XSS Using Alternate Syntax  `SC04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-470 — Removing Important Client Functionality  `SC05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-472 — Exploitation of Trusted Credentials  `AA03`

- **Element:** OpenCTI platform (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-475 — Exploiting Trust in Client  `AA04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-479 — XML Attribute Blowup  `INP22`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-480 — XSS Targeting URI Placeholders  `INP28`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-482 — SOAP Array Overflow  `INP34`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-484 — HTTP Request Smuggling  `INP37`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-485 — Session Credential Falsification through Prediction  `AC16`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-487 — Reusing Session IDs (aka Session Replay) - ServerSide  `AC19`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-492 — Audit Log Manipulation  `DE04`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — OpenCTI's own audit trail lives in its backing stores and is the platform's.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-500 — Format String Injection  `INP08`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-501 — Client-side Injection-induced Buffer Overflow  `INP12`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** The client software should not install untrusted code from a non-authenticated server. The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers. Perform input validation for length of buffer inputs. Use a language or compiler that performs automatic bounds checking. Use an abstraction library to abstract away risky APIs. Not a complete solution. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Ensure all buffer uses are consistently bounds-checked. Use OS-level preventative functionality. Not a complete solution.

#### F-502 — Command Delimiters  `INP13`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Perform whitelist validation against a positive specification for command length, type, and parameters.Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running under a privileged accountImplementation: Perform input validation for all remote content.Implementation: Use type conversions such as JDBC prepared statements.

#### F-504 — Dictionary-based Password Attack  `CR03`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-506 — iFrame Overlay  `INP20`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Configuration: Disable iFrames in the Web browser.Operation: When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.Operation: If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.

#### F-508 — Privilege Escalation  `AC12`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-511 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-512 — Resource Injection  `INP25`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Ensure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-513 — Code Injection  `INP26`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Utilize strict type, character, and encoding enforcementEnsure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-515 — XSS Targeting URI Placeholders  `INP28`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-518 — Command Injection  `INP31`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary.Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter.Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.

#### F-519 — XML Injection  `INP32`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.

#### F-520 — Remote Code Inclusion  `INP33`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize attacks by input validation and sanitization of any user data that will be used by the target application to locate a remote file to be included.

#### F-521 — Leverage Alternate Encoding  `INP35`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input.

#### F-522 — Schema Poisoning  `AC15`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Schema handling inside oauth2-proxy and connector-misp is upstream's; the orchestrator validates everything it receives from either side.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-524 — Argument Injection  `INP41`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out all unauthorized commands and characters in the process.Design: Limit program privileges, so if metacharacters or other methods circumvent program input validation routines and shell access is attained then it is not running under a privileged account. chroot jails create a sandbox for the application to execute in, making it more difficult for an attacker to elevate privilege even in the case that a compromise has occurred.Implementation: Implement an audit log that is written to a separate host, in the event of a compromise the audit log may be able to provide evidence and details of the compromise.

#### F-525 — Reusing Session IDs (aka Session Replay) - ClientSide  `AC20`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-527 — Session Sidejacking  `CR01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback and hardcodes OAUTH2_PROXY_COOKIE_SECURE=false (no variable reads it): the session cookie is exposed to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front of the proxy and a Compose override that sets OAUTH2_PROXY_COOKIE_SECURE to true.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-532 — Communication Channel Manipulation  `CR06`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-535 — Unprotected Sensitive Data  `DR01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-536 — Credentials Disclosure  `AC23`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-537 — Session Sidejacking  `CR01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback and hardcodes OAUTH2_PROXY_COOKIE_SECURE=false (no variable reads it): the session cookie is exposed to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front of the proxy and a Compose override that sets OAUTH2_PROXY_COOKIE_SECURE to true.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-542 — Communication Channel Manipulation  `CR06`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-544 — Unprotected Sensitive Data  `DR01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-545 — Credentials Disclosure  `AC23`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-549 — Communication Channel Manipulation  `CR06`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-551 — Unprotected Sensitive Data  `DR01`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-552 — Credentials Disclosure  `AC23`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-556 — Communication Channel Manipulation  `CR06`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-559 — Unprotected Sensitive Data  `DR01`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-560 — Credentials Disclosure  `AC23`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-564 — Communication Channel Manipulation  `CR06`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-567 — Unprotected Sensitive Data  `DR01`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-568 — Credentials Disclosure  `AC23`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-572 — Communication Channel Manipulation  `CR06`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-577 — Communication Channel Manipulation  `CR06`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-580 — Unprotected Sensitive Data  `DR01`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-581 — Credentials Disclosure  `AC23`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-585 — Communication Channel Manipulation  `CR06`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-590 — Communication Channel Manipulation  `CR06`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-595 — Communication Channel Manipulation  `CR06`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-600 — Communication Channel Manipulation  `CR06`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-605 — Communication Channel Manipulation  `CR06`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-610 — Communication Channel Manipulation  `CR06`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-612 — Credentials Disclosure  `AC23`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-616 — Communication Channel Manipulation  `CR06`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-619 — Unprotected Sensitive Data  `DR01`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-623 — Communication Channel Manipulation  `CR06`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-628 — Communication Channel Manipulation  `CR06`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-629 — Credentials Disclosure  `AC23`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-633 — Communication Channel Manipulation  `CR06`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-634 — Credentials Disclosure  `AC23`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-638 — Communication Channel Manipulation  `CR06`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-640 — Unprotected Sensitive Data  `DR01`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-644 — Communication Channel Manipulation  `CR06`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-646 — Unprotected Sensitive Data  `DR01`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-650 — Communication Channel Manipulation  `CR06`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-651 — Credentials Disclosure  `AC23`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-655 — Communication Channel Manipulation  `CR06`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-658 — Unprotected Sensitive Data  `DR01`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-662 — Communication Channel Manipulation  `CR06`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-667 — Communication Channel Manipulation  `CR06`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-670 — Unprotected Sensitive Data  `DR01`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-674 — Communication Channel Manipulation  `CR06`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-679 — Communication Channel Manipulation  `CR06`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-684 — Communication Channel Manipulation  `CR06`

- **Element:** Local model inference (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-689 — Communication Channel Manipulation  `CR06`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-690 — Credentials Disclosure  `AC23`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-694 — Communication Channel Manipulation  `CR06`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-699 — Communication Channel Manipulation  `CR06`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-704 — Communication Channel Manipulation  `CR06`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-709 — Communication Channel Manipulation  `CR06`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-711 — Unprotected Sensitive Data  `DR01`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-712 — Credentials Disclosure  `AC23`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-716 — Communication Channel Manipulation  `CR06`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-721 — Communication Channel Manipulation  `CR06`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-723 — Unprotected Sensitive Data  `DR01`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-724 — Credentials Disclosure  `AC23`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-728 — Communication Channel Manipulation  `CR06`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-730 — Unprotected Sensitive Data  `DR01`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-731 — Credentials Disclosure  `AC23`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-735 — Communication Channel Manipulation  `CR06`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-740 — Communication Channel Manipulation  `CR06`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-741 — Credentials Disclosure  `AC23`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-745 — Communication Channel Manipulation  `CR06`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-747 — Unprotected Sensitive Data  `DR01`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, the SocialOSINT cache, OpenCTI stores) and host-internal hops carry it in clear; credentials and personal data travel only to the service they belong to, under TLS when they leave the host. Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-748 — Credentials Disclosure  `AC23`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-752 — Communication Channel Manipulation  `CR06`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-753 — Credentials Disclosure  `AC23`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-757 — Communication Channel Manipulation  `CR06`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-758 — Credentials Disclosure  `AC23`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

### Severity: Medium (358)

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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-96 — Double Encoding  `DE02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-97 — Privilege Abuse  `AC01`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-150 — Principal Spoof  `AA02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
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

#### F-175 — Authentication Abuse/ByPass  `AA01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests) under the assumption that ORCHESTRATOR_API_KEY is set; /health and /metrics are intentionally open; the console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-177 — Flooding  `DO01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** accepted — No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-178 — Excessive Allocation  `DO02`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** accepted — Per-run budgets cap the collectors and the models (TAVILY_MAX_CALLS_PER_RUN, LLM_QUALIFY_MAX_ITEMS, LLM_MAX_TOKENS), but POST /bundles reads the whole body with request.json() before validating it and no middleware caps uploads, so an authenticated producer can exhaust memory with one request. Hardening: a body-size limit at the reverse proxy or TLS terminator in front of :8000.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-179 — Principal Spoof  `AA02`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds an authenticated person (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-181 — Hijacking a privileged process  `AC13`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-187 — Authentication Abuse/ByPass  `AA01`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests) under the assumption that ORCHESTRATOR_API_KEY is set; /health and /metrics are intentionally open; the console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-188 — Flooding  `DO01`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** accepted — No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-189 — Excessive Allocation  `DO02`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** accepted — Per-run budgets cap the collectors and the models (TAVILY_MAX_CALLS_PER_RUN, LLM_QUALIFY_MAX_ITEMS, LLM_MAX_TOKENS), but POST /bundles reads the whole body with request.json() before validating it and no middleware caps uploads, so an authenticated producer can exhaust memory with one request. Hardening: a body-size limit at the reverse proxy or TLS terminator in front of :8000.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-190 — Principal Spoof  `AA02`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds an authenticated person (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-192 — Hijacking a privileged process  `AC13`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-196 — Privilege Abuse  `AC01`

- **Element:** SQLite run store (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, the SocialOSINT sidecar for its cache); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-197 — Excessive Allocation  `DO02`

- **Element:** SQLite run store (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-200 — Privilege Abuse  `AC01`

- **Element:** targets.yaml (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, the SocialOSINT sidecar for its cache); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-201 — Excessive Allocation  `DO02`

- **Element:** targets.yaml (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-204 — Privilege Abuse  `AC01`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, the SocialOSINT sidecar for its cache); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-205 — Excessive Allocation  `DO02`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-208 — Privilege Abuse  `AC01`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, the SocialOSINT sidecar for its cache); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-209 — Shared Data Manipulation  `AC02`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — The Amass asset database is shared between the engine and the orchestrator on one volume of the trusted host (ADR-005); oam_subs output is parsed as untrusted text.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. Use HTTPS/SSL for communication.

#### F-210 — Excessive Allocation  `DO02`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-216 — Authentication Abuse/ByPass  `AA01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-217 — Excavation  `DS01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-218 — Double Encoding  `DE02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-219 — Privilege Abuse  `AC01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-220 — Flooding  `DO01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-222 — Excessive Allocation  `DO02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-225 — Parameter Injection  `INP10`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-227 — Input Data Manipulation  `INP14`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-233 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-236 — Principal Spoof  `AA02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-237 — XSS Targeting Error Pages  `DS04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-240 — Manipulate Registry Information  `AC08`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-242 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-244 — Functionality Misuse  `AC09`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-247 — XML External Entities Blowup  `INP19`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-248 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-249 — DTD Injection  `INP21`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-252 — XSS Using Doubled Characters  `INP29`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-254 — HTTP Response Smuggling  `INP36`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-261 — Authentication Abuse/ByPass  `AA01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-262 — Excavation  `DS01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-263 — Double Encoding  `DE02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-264 — Privilege Abuse  `AC01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-265 — Flooding  `DO01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-267 — Excessive Allocation  `DO02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-270 — Parameter Injection  `INP10`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-272 — Input Data Manipulation  `INP14`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-278 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-281 — Principal Spoof  `AA02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-282 — XSS Targeting Error Pages  `DS04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-285 — Manipulate Registry Information  `AC08`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-287 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-289 — Functionality Misuse  `AC09`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-292 — XML External Entities Blowup  `INP19`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-293 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-294 — DTD Injection  `INP21`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-297 — XSS Using Doubled Characters  `INP29`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-299 — HTTP Response Smuggling  `INP36`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-306 — Authentication Abuse/ByPass  `AA01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-307 — Excavation  `DS01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-308 — Double Encoding  `DE02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-309 — Privilege Abuse  `AC01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-310 — Flooding  `DO01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-312 — Excessive Allocation  `DO02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-315 — Parameter Injection  `INP10`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-317 — Input Data Manipulation  `INP14`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-323 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-326 — Principal Spoof  `AA02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-327 — XSS Targeting Error Pages  `DS04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-330 — Manipulate Registry Information  `AC08`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-332 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-334 — Functionality Misuse  `AC09`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-337 — XML External Entities Blowup  `INP19`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-338 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-339 — DTD Injection  `INP21`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-342 — XSS Using Doubled Characters  `INP29`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-344 — HTTP Response Smuggling  `INP36`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-348 — Privilege Abuse  `AC01`

- **Element:** SocialOSINT cache volume (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db, the SocialOSINT sidecar for its cache); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-349 — Excessive Allocation  `DO02`

- **Element:** SocialOSINT cache volume (store)
- **Response:** accepted — No retention reaches this volume: the sidecar's CacheManager keeps profiles and posts under /app/data until the operator removes the volume or prunes it, and deleting a session removes only the session file. The orchestrator keeps nothing of it beyond the unverified note. Hardening: an ephemeral (tmpfs) volume or a purge job for /app/data, sized to the retention the operator owes the people in those profiles.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-355 — Authentication Abuse/ByPass  `AA01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-356 — Excavation  `DS01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-357 — Double Encoding  `DE02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-358 — Privilege Abuse  `AC01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-359 — Flooding  `DO01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-361 — Excessive Allocation  `DO02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-364 — Parameter Injection  `INP10`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-366 — Input Data Manipulation  `INP14`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-372 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-375 — Principal Spoof  `AA02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-376 — XSS Targeting Error Pages  `DS04`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-379 — Manipulate Registry Information  `AC08`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-381 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-383 — Functionality Misuse  `AC09`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-386 — XML External Entities Blowup  `INP19`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-387 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-388 — DTD Injection  `INP21`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-391 — XSS Using Doubled Characters  `INP29`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-393 — HTTP Response Smuggling  `INP36`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-402 — Excavation  `DS01`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-403 — Double Encoding  `DE02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-404 — Privilege Abuse  `AC01`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-405 — Flooding  `DO01`

- **Element:** MISP (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-407 — Excessive Allocation  `DO02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-410 — Parameter Injection  `INP10`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-412 — Input Data Manipulation  `INP14`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-418 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-421 — XSS Targeting Error Pages  `DS04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-424 — Manipulate Registry Information  `AC08`

- **Element:** MISP (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-426 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** MISP (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-428 — Functionality Misuse  `AC09`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-431 — XML External Entities Blowup  `INP19`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-432 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** MISP (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-433 — DTD Injection  `INP21`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-436 — XSS Using Doubled Characters  `INP29`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-438 — HTTP Response Smuggling  `INP36`

- **Element:** MISP (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-447 — Authentication Abuse/ByPass  `AA01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-448 — Excavation  `DS01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-449 — Double Encoding  `DE02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-450 — Privilege Abuse  `AC01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-451 — Flooding  `DO01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-453 — Excessive Allocation  `DO02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-456 — Parameter Injection  `INP10`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-458 — Input Data Manipulation  `INP14`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-465 — Principal Spoof  `AA02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-466 — Session Credential Falsification through Forging  `CR04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-467 — XSS Targeting Error Pages  `DS04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-471 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-473 — Functionality Misuse  `AC09`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-476 — XML External Entities Blowup  `INP19`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-477 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-478 — DTD Injection  `INP21`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-481 — XSS Using Doubled Characters  `INP29`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-483 — HTTP Response Smuggling  `INP36`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-488 — Privilege Abuse  `AC01`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-489 — Shared Data Manipulation  `AC02`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — OpenCTI's backing stores (Elasticsearch, MinIO, RabbitMQ, Redis) are owned and hardened by the OpenCTI platform deployment.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. Use HTTPS/SSL for communication.

#### F-490 — Excessive Allocation  `DO02`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-494 — Authentication Abuse/ByPass  `AA01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-495 — Double Encoding  `DE02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-496 — Privilege Abuse  `AC01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-498 — Flooding  `DO01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-499 — Excessive Allocation  `DO02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-503 — Input Data Manipulation  `INP14`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-505 — Principal Spoof  `AA02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-509 — Hijacking a privileged process  `AC13`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-514 — XSS Targeting HTML Attributes  `INP27`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list all input including that which is not expected to have any scripting content.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-516 — XSS Using Doubled Characters  `INP29`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-517 — XSS Using Invalid Characters  `INP30`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be included in any subsequent web pages or back end operations.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-529 — Interception  `DE01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-530 — Content Spoofing  `AC05`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-531 — Sniffing Attacks  `DE03`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-533 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-539 — Interception  `DE01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-540 — Content Spoofing  `AC05`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-541 — Sniffing Attacks  `DE03`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-543 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-546 — Interception  `DE01`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-547 — Content Spoofing  `AC05`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-548 — Sniffing Attacks  `DE03`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-550 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-553 — Interception  `DE01`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-554 — Content Spoofing  `AC05`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-555 — Sniffing Attacks  `DE03`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-557 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-561 — Interception  `DE01`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-562 — Content Spoofing  `AC05`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-563 — Sniffing Attacks  `DE03`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-565 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-569 — Interception  `DE01`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-570 — Content Spoofing  `AC05`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-571 — Sniffing Attacks  `DE03`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-573 — Client-Server Protocol Manipulation  `CR08`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-574 — Interception  `DE01`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-575 — Content Spoofing  `AC05`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-576 — Sniffing Attacks  `DE03`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-578 — Client-Server Protocol Manipulation  `CR08`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-582 — Interception  `DE01`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-583 — Content Spoofing  `AC05`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-584 — Sniffing Attacks  `DE03`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-586 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-587 — Interception  `DE01`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-588 — Content Spoofing  `AC05`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-589 — Sniffing Attacks  `DE03`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-591 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Scan control & results (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-592 — Interception  `DE01`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-593 — Content Spoofing  `AC05`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-594 — Sniffing Attacks  `DE03`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-596 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-597 — Interception  `DE01`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-598 — Content Spoofing  `AC05`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-599 — Sniffing Attacks  `DE03`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-601 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-602 — Interception  `DE01`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-603 — Content Spoofing  `AC05`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-604 — Sniffing Attacks  `DE03`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-606 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-607 — Interception  `DE01`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-608 — Content Spoofing  `AC05`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-609 — Sniffing Attacks  `DE03`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-613 — Interception  `DE01`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-614 — Content Spoofing  `AC05`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-615 — Sniffing Attacks  `DE03`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-617 — Client-Server Protocol Manipulation  `CR08`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-620 — Interception  `DE01`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-621 — Content Spoofing  `AC05`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-622 — Sniffing Attacks  `DE03`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-624 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-625 — Interception  `DE01`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-626 — Content Spoofing  `AC05`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-627 — Sniffing Attacks  `DE03`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-630 — Interception  `DE01`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-631 — Content Spoofing  `AC05`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-632 — Sniffing Attacks  `DE03`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-635 — Interception  `DE01`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-636 — Content Spoofing  `AC05`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-637 — Sniffing Attacks  `DE03`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-639 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Cache collected profiles and posts (/app/data) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-641 — Interception  `DE01`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-642 — Content Spoofing  `AC05`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-643 — Sniffing Attacks  `DE03`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-645 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read cached profiles for later sessions (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-647 — Interception  `DE01`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-648 — Content Spoofing  `AC05`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-649 — Sniffing Attacks  `DE03`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-652 — Interception  `DE01`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-653 — Content Spoofing  `AC05`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-654 — Sniffing Attacks  `DE03`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-656 — Client-Server Protocol Manipulation  `CR08`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-659 — Interception  `DE01`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-660 — Content Spoofing  `AC05`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-661 — Sniffing Attacks  `DE03`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-664 — Interception  `DE01`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-665 — Content Spoofing  `AC05`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-666 — Sniffing Attacks  `DE03`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-668 — Client-Server Protocol Manipulation  `CR08`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-671 — Interception  `DE01`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-672 — Content Spoofing  `AC05`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-673 — Sniffing Attacks  `DE03`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-676 — Interception  `DE01`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-677 — Content Spoofing  `AC05`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-678 — Sniffing Attacks  `DE03`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-680 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-681 — Interception  `DE01`

- **Element:** Local model inference (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-682 — Content Spoofing  `AC05`

- **Element:** Local model inference (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-683 — Sniffing Attacks  `DE03`

- **Element:** Local model inference (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-685 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Local model inference (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-686 — Interception  `DE01`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-687 — Content Spoofing  `AC05`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-688 — Sniffing Attacks  `DE03`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-691 — Interception  `DE01`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-692 — Content Spoofing  `AC05`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-693 — Sniffing Attacks  `DE03`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-695 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-696 — Interception  `DE01`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-697 — Content Spoofing  `AC05`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-698 — Sniffing Attacks  `DE03`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-700 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-701 — Interception  `DE01`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-702 — Content Spoofing  `AC05`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-703 — Sniffing Attacks  `DE03`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-705 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read target inventory (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-706 — Interception  `DE01`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-707 — Content Spoofing  `AC05`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-708 — Sniffing Attacks  `DE03`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-710 — Client-Server Protocol Manipulation  `CR08`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-713 — Interception  `DE01`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-714 — Content Spoofing  `AC05`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-715 — Sniffing Attacks  `DE03`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-717 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-718 — Interception  `DE01`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-719 — Content Spoofing  `AC05`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-720 — Sniffing Attacks  `DE03`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-722 — Client-Server Protocol Manipulation  `CR08`

- **Element:** MinIO objects (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-725 — Interception  `DE01`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-726 — Content Spoofing  `AC05`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-727 — Sniffing Attacks  `DE03`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-729 — Client-Server Protocol Manipulation  `CR08`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-732 — Interception  `DE01`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-733 — Content Spoofing  `AC05`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-734 — Sniffing Attacks  `DE03`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-736 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-737 — Interception  `DE01`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-738 — Content Spoofing  `AC05`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-739 — Sniffing Attacks  `DE03`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-742 — Interception  `DE01`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-743 — Content Spoofing  `AC05`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-744 — Sniffing Attacks  `DE03`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-746 — Client-Server Protocol Manipulation  `CR08`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-749 — Interception  `DE01`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-750 — Content Spoofing  `AC05`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-751 — Sniffing Attacks  `DE03`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-754 — Interception  `DE01`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-755 — Content Spoofing  `AC05`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-756 — Sniffing Attacks  `DE03`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

### Severity: Low (33)

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

#### F-198 — Encryption Brute Forcing  `CR05`

- **Element:** SQLite run store (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-202 — Encryption Brute Forcing  `CR05`

- **Element:** targets.yaml (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-206 — Encryption Brute Forcing  `CR05`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-211 — Encryption Brute Forcing  `CR05`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-231 — Web Application Fingerprinting  `HA03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-239 — Encryption Brute Forcing  `CR05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-245 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-276 — Web Application Fingerprinting  `HA03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-284 — Encryption Brute Forcing  `CR05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-290 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-321 — Web Application Fingerprinting  `HA03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-329 — Encryption Brute Forcing  `CR05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-335 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-350 — Encryption Brute Forcing  `CR05`

- **Element:** SocialOSINT cache volume (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-370 — Web Application Fingerprinting  `HA03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-378 — Encryption Brute Forcing  `CR05`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-384 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-416 — Web Application Fingerprinting  `HA03`

- **Element:** MISP (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-423 — Encryption Brute Forcing  `CR05`

- **Element:** MISP (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-429 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-461 — Web Application Fingerprinting  `HA03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-469 — Encryption Brute Forcing  `CR05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-474 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-491 — Encryption Brute Forcing  `CR05`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

### Severity: Very Low (9)

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

#### F-229 — Footprinting  `DS03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-274 — Footprinting  `DS03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-319 — Footprinting  `DS03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-368 — Footprinting  `DS03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-414 — Footprinting  `DS03`

- **Element:** MISP (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-459 — Footprinting  `DS03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.
