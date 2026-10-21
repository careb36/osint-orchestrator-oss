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

## Element classes

A response is written per class: the same threat means something different on the orchestrator, on an unauthenticated sidecar, on a vendor service, on a store or on a flow.

- **orchestrator**: Orchestrator API (FastAPI + APScheduler), APScheduler cron jobs
- **sidecar**: SpiderFoot, Amass v5 engine, SocialOSINT sidecar, Ollama (local models), Ollama HTTP API
- **vendor**: Tavily search API, Cloud LLM provider, SocialOSINT's LLM endpoint, SMTP relay (alert e-mail), Alert webhook receiver, oauth2-proxy, Keycloak, MISP, OpenCTI platform, OpenCTI backing stores, connector-misp
- **store**: SQLite run store, targets.yaml, daily_reports (sealed runs), Amass asset database (shared volume)
- **flow**: every dataflow, named by what it carries

## Findings: 766 across 86 distinct threats

Every finding carries a triage response:

- **accepted**: 451 finding(s)
- **mitigated**: 21 finding(s)
- **transferred**: 294 finding(s)

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
| AC01 Privilege Abuse | Medium | store | accepted | One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible. |
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
| DE04 Audit Log Manipulation | High | store | mitigated | Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper. |
| DE04 Audit Log Manipulation | High | vendor | transferred | OpenCTI's own audit trail lives in its backing stores and is the platform's. |
| DO01 Flooding | Medium | orchestrator | accepted | No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator. |
| DO01 Flooding | Medium | sidecar | accepted | The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps. |
| DO01 Flooding | Medium | vendor | transferred | Rate limiting of vendor services is the vendor's. |
| DO02 Excessive Allocation | Medium | orchestrator | accepted | Per-run budgets cap the collectors and the models (TAVILY_MAX_CALLS_PER_RUN, LLM_QUALIFY_MAX_ITEMS, LLM_MAX_TOKENS), but POST /bundles reads the whole body with request.json() before validating it and no middleware caps uploads, so an authenticated producer can exhaust memory with one request. Hardening: a body-size limit at the reverse proxy or TLS terminator in front of :8000. |
| DO02 Excessive Allocation | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DO02 Excessive Allocation | Medium | store | accepted | Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes. |
| DO02 Excessive Allocation | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DR01 Unprotected Sensitive Data | High | flow | accepted | Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
| DS01 Excavation | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DS01 Excavation | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DS03 Footprinting | Very Low | sidecar | accepted | Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments. |
| DS03 Footprinting | Very Low | vendor | transferred | Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment. |
| DS04 XSS Targeting Error Pages | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DS04 XSS Targeting Error Pages | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DS06 Data Leak | Very High | flow | accepted | Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input. |
| HA01 Path Traversal | Very High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| HA01 Path Traversal | Very High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| HA03 Web Application Fingerprinting | Low | sidecar | accepted | SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself. |
| HA03 Web Application Fingerprinting | Low | vendor | transferred | Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services. |
| INP02 Overflow Buffers | Very High | orchestrator | mitigated | Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS) and LLM_MAX_OBSERVABLES_IN_PROMPT. |
| INP02 Overflow Buffers | Very High | vendor | transferred | oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code. |
| INP03 Server Side Include (SSI) Injection | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| INP03 Server Side Include (SSI) Injection | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
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
| LLM03 Sensitive Data Leakage to Third-Party Provider | High | vendor | accepted | The prompts carry personal data of the target's public footprint with no redaction: the orchestrator sends the observables it collected (domains, URLs, e-mail addresses, phone numbers, person names) and SocialOSINT sends profiles, posts and images to its own endpoint. Both go only to the provider the operator configured, over TLS; `llm: local` keeps the orchestrator's prompts on the host. Hardening: a provider under a data-processing agreement with retention and training opted out, or local models for sensitive workloads. |
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

### Severity: Very High (96)

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

#### F-92 — Session Hijacking - ServerSide  `AC17`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-93 — Overflow Buffers  `INP02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-97 — Buffer Manipulation  `INP07`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** To help protect an application from buffer manipulation attacks, a number of potential mitigations can be leveraged. Before starting the development of the application, consider using a code language (e.g., Java) or compiler that limits the ability of developers to act beyond the bounds of a buffer. If the chosen language is susceptible to buffer related issues (e.g., C) then consider using secure functions instead of those vulnerable to buffer manipulations. If a potentially dangerous function must be used, make sure that proper boundary checking is performed. Additionally, there are often a number of compiler-based mechanisms (e.g., StackGuard, ProPolice and the Microsoft Visual Studio /GS flag) that can help identify and protect against potential buffer issues. Finally, there may be operating system level preventative functionality that can be applied.

#### F-106 — File Content Injection  `INP23`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Validate all input for content including files. Ensure that if files and remote content must be accepted that once accepted, they are placed in a sandbox type location so that lower assurance clients cannot write up to higher assurance processes (like Web server processes for example)Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.Implementation: Virus scanning on hostImplementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.

#### F-109 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-122 — Session Hijacking - ClientSide  `AC18`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-127 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-133 — Path Traversal  `HA01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-141 — Using Malicious Files  `AC06`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-143 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-169 — Session Hijacking - ServerSide  `AC17`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-171 — Overflow Buffers  `INP02`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS) and LLM_MAX_OBSERVABLES_IN_PROMPT.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-179 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — The pipeline isolates every step (collect, qualify, normalise, synthesise, seal, alert): a raised error fails the run, never a privileged transaction; the process runs as uid 1000 with no setuid paths (Dockerfile).
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-182 — Cross Site Request Forgery  `AC21`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no ambient credential to forge cross-site; the console CSP sets form-action 'none'; the scheduler has no HTTP surface. The OIDC overlay adds oauth2-proxy's CSRF token.
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-183 — Overflow Buffers  `INP02`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS) and LLM_MAX_OBSERVABLES_IN_PROMPT.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-192 — Cross Site Request Forgery  `AC21`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no ambient credential to forge cross-site; the console CSP sets form-action 'none'; the scheduler has no HTTP surface. The OIDC overlay adds oauth2-proxy's CSRF token.
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-211 — Command Line Execution through SQL Injection  `INP05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-217 — Path Traversal  `HA01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-226 — Using Malicious Files  `AC06`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-228 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-253 — Session Hijacking - ServerSide  `AC17`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-255 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-261 — Path Traversal  `HA01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-270 — Using Malicious Files  `AC06`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-272 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-297 — Session Hijacking - ServerSide  `AC17`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-299 — Command Line Execution through SQL Injection  `INP05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-305 — Path Traversal  `HA01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-314 — Using Malicious Files  `AC06`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-316 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-341 — Session Hijacking - ServerSide  `AC17`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-343 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-349 — Path Traversal  `HA01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-358 — Using Malicious Files  `AC06`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-360 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-385 — Session Hijacking - ServerSide  `AC17`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-390 — Command Line Execution through SQL Injection  `INP05`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-395 — Path Traversal  `HA01`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-404 — Using Malicious Files  `AC06`

- **Element:** MISP (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-406 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-430 — Session Hijacking - ServerSide  `AC17`

- **Element:** MISP (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-433 — Command Line Execution through SQL Injection  `INP05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-439 — Path Traversal  `HA01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-447 — Using Malicious Files  `AC06`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-449 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-473 — Session Hijacking - ServerSide  `AC17`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-480 — Overflow Buffers  `INP02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-484 — Buffer Manipulation  `INP07`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** To help protect an application from buffer manipulation attacks, a number of potential mitigations can be leveraged. Before starting the development of the application, consider using a code language (e.g., Java) or compiler that limits the ability of developers to act beyond the bounds of a buffer. If the chosen language is susceptible to buffer related issues (e.g., C) then consider using secure functions instead of those vulnerable to buffer manipulations. If a potentially dangerous function must be used, make sure that proper boundary checking is performed. Additionally, there are often a number of compiler-based mechanisms (e.g., StackGuard, ProPolice and the Microsoft Visual Studio /GS flag) that can help identify and protect against potential buffer issues. Finally, there may be operating system level preventative functionality that can be applied.

#### F-494 — File Content Injection  `INP23`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Validate all input for content including files. Ensure that if files and remote content must be accepted that once accepted, they are placed in a sandbox type location so that lower assurance clients cannot write up to higher assurance processes (like Web server processes for example)Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.Implementation: Virus scanning on hostImplementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.

#### F-497 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-510 — Session Hijacking - ClientSide  `AC18`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-513 — Cross Site Request Forgery  `AC21`

- **Element:** connector-misp (vendor)
- **Response:** transferred — connector-misp has no browser-facing surface; CSRF on vendor UIs is the vendor's (oauth2-proxy implements its own CSRF token).
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-515 — Cross Site Tracing  `CR02`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — FastAPI answers TRACE with 405 and the console ships no inline script that could read reflected headers; the plaintext proxied hop itself is the DS06 decision (shipped overlay without TLS). Hardening: TLS terminator that drops TRACE.
- **pytm mitigations:** Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.

#### F-521 — Data Leak  `DS06`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-525 — Cross Site Tracing  `CR02`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — FastAPI answers TRACE with 405 and the console ships no inline script that could read reflected headers; the plaintext proxied hop itself is the DS06 decision (shipped overlay without TLS). Hardening: TLS terminator that drops TRACE.
- **pytm mitigations:** Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.

#### F-531 — Data Leak  `DS06`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-539 — Data Leak  `DS06`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-547 — Data Leak  `DS06`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-555 — Data Leak  `DS06`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-568 — Data Leak  `DS06`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-581 — Data Leak  `DS06`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-593 — Data Leak  `DS06`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-600 — Data Leak  `DS06`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-606 — Data Leak  `DS06`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-613 — Data Leak  `DS06`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-620 — Data Leak  `DS06`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-626 — Data Leak  `DS06`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-632 — Data Leak  `DS06`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-638 — Data Leak  `DS06`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-645 — Data Leak  `DS06`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-651 — Data Leak  `DS06`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-657 — Data Leak  `DS06`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-663 — Data Leak  `DS06`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-669 — Data Leak  `DS06`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-676 — Data Leak  `DS06`

- **Element:** Local model inference (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-682 — Data Leak  `DS06`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-689 — Data Leak  `DS06`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-696 — Data Leak  `DS06`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-708 — Data Leak  `DS06`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-716 — Data Leak  `DS06`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-723 — Data Leak  `DS06`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-731 — Data Leak  `DS06`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-739 — Data Leak  `DS06`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-745 — Data Leak  `DS06`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-752 — Data Leak  `DS06`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-759 — Data Leak  `DS06`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-765 — Data Leak  `DS06`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

### Severity: High (282)

#### F-1 — Direct Prompt Injection  `LLM01`

- **Element:** SocialOSINT's LLM endpoint (vendor)
- **Response:** accepted — SocialOSINT sends its own prompts (profiles, posts, images) to this endpoint and gets a free-text Markdown report back. The orchestrator attaches that report as a note labelled unverified (collectors/socialosint.py), never as observables, with no schema validation; the console renders it escaped and nothing acts on it. Residual risk: a manipulated report misleads the analyst who reads the note.
- **pytm mitigations:** Implement input content filtering and guardrails. Use prompt engineering techniques to make the system prompt more robust against injection. Apply output validation to detect and block manipulated responses. Monitor and log prompts for anomalous patterns.

#### F-2 — Sensitive Data Leakage to Third-Party Provider  `LLM03`

- **Element:** SocialOSINT's LLM endpoint (vendor)
- **Response:** accepted — The prompts carry personal data of the target's public footprint with no redaction: the orchestrator sends the observables it collected (domains, URLs, e-mail addresses, phone numbers, person names) and SocialOSINT sends profiles, posts and images to its own endpoint. Both go only to the provider the operator configured, over TLS; `llm: local` keeps the orchestrator's prompts on the host. Hardening: a provider under a data-processing agreement with retention and training opted out, or local models for sensitive workloads.
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
- **Response:** accepted — The prompts carry personal data of the target's public footprint with no redaction: the orchestrator sends the observables it collected (domains, URLs, e-mail addresses, phone numbers, person names) and SocialOSINT sends profiles, posts and images to its own endpoint. Both go only to the provider the operator configured, over TLS; `llm: local` keeps the orchestrator's prompts on the host. Hardening: a provider under a data-processing agreement with retention and training opted out, or local models for sensitive workloads.
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

#### F-70 — Embedding Scripts within Scripts  `SC03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-71 — PHP Remote File Inclusion  `INP16`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-73 — XSS Using Alternate Syntax  `SC04`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-76 — Removing Important Client Functionality  `SC05`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-78 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-81 — Exploiting Trust in Client  `AA04`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-85 — XML Attribute Blowup  `INP22`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-86 — XSS Targeting URI Placeholders  `INP28`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-88 — SOAP Array Overflow  `INP34`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-90 — HTTP Request Smuggling  `INP37`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-91 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-100 — Format String Injection  `INP08`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-101 — Client-side Injection-induced Buffer Overflow  `INP12`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** The client software should not install untrusted code from a non-authenticated server. The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers. Perform input validation for length of buffer inputs. Use a language or compiler that performs automatic bounds checking. Use an abstraction library to abstract away risky APIs. Not a complete solution. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Ensure all buffer uses are consistently bounds-checked. Use OS-level preventative functionality. Not a complete solution.

#### F-102 — Command Delimiters  `INP13`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Perform whitelist validation against a positive specification for command length, type, and parameters.Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running under a privileged accountImplementation: Perform input validation for all remote content.Implementation: Use type conversions such as JDBC prepared statements.

#### F-105 — iFrame Overlay  `INP20`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Configuration: Disable iFrames in the Web browser.Operation: When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.Operation: If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.

#### F-107 — Privilege Escalation  `AC12`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-110 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-111 — Resource Injection  `INP25`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Ensure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-112 — Code Injection  `INP26`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Utilize strict type, character, and encoding enforcementEnsure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-114 — XSS Targeting URI Placeholders  `INP28`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-117 — Command Injection  `INP31`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary.Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter.Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.

#### F-118 — XML Injection  `INP32`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.

#### F-119 — Remote Code Inclusion  `INP33`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize attacks by input validation and sanitization of any user data that will be used by the target application to locate a remote file to be included.

#### F-120 — Leverage Alternate Encoding  `INP35`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input.

#### F-121 — Schema Poisoning  `AC15`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Schema handling inside oauth2-proxy and connector-misp is upstream's; the orchestrator validates everything it receives from either side.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-123 — Argument Injection  `INP41`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out all unauthorized commands and characters in the process.Design: Limit program privileges, so if metacharacters or other methods circumvent program input validation routines and shell access is attained then it is not running under a privileged account. chroot jails create a sandbox for the application to execute in, making it more difficult for an attacker to elevate privilege even in the case that a compromise has occurred.Implementation: Implement an audit log that is written to a separate host, in the event of a compromise the audit log may be able to provide evidence and details of the compromise.

#### F-124 — Reusing Session IDs (aka Session Replay) - ClientSide  `AC20`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-125 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-126 — Session Sidejacking  `CR01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-135 — Format String Injection  `INP08`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-136 — LDAP Injection  `INP09`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-138 — Relative Path Traversal  `INP11`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-145 — Embedding Scripts within Scripts  `SC03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-146 — PHP Remote File Inclusion  `INP16`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-150 — XSS Using Alternate Syntax  `SC04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-153 — Removing Important Client Functionality  `SC05`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-155 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Keycloak (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-158 — Exploiting Trust in Client  `AA04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-162 — XML Attribute Blowup  `INP22`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-163 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-165 — SOAP Array Overflow  `INP34`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-167 — HTTP Request Smuggling  `INP37`

- **Element:** Keycloak (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-168 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-170 — Reusing Session IDs (aka Session Replay) - ServerSide  `AC19`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-173 — Exploit Test APIs  `API01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — No test or debug endpoints ship; /docs is the read-only OpenAPI UI and every data route behind it still requires the API key (tests assert 401 without it).
- **pytm mitigations:** Ensure that production systems to not contain sample or test APIs and that these APIs are only used in development environments.

#### F-177 — Privilege Escalation  `AC12`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-180 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-181 — Schema Poisoning  `AC15`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-188 — Privilege Escalation  `AC12`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-190 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-191 — Schema Poisoning  `AC15`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-196 — Audit Log Manipulation  `DE04`

- **Element:** SQLite run store (store)
- **Response:** accepted — Run rows are outside the manifest chain: /targets/{id}/chain/verify checks the manifest hash, signature, chain link and artefact files (evidence.py), not a row's status, collectors or timestamps, so an edit to those fields with the manifest intact goes undetected. Hardening: database file permissions, backups and disk encryption.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-200 — Audit Log Manipulation  `DE04`

- **Element:** targets.yaml (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-204 — Audit Log Manipulation  `DE04`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-209 — Audit Log Manipulation  `DE04`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-210 — Server Side Include (SSI) Injection  `INP03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-219 — Format String Injection  `INP08`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-220 — LDAP Injection  `INP09`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-222 — Relative Path Traversal  `INP11`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-224 — Dictionary-based Password Attack  `CR03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-230 — Embedding Scripts within Scripts  `SC03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-231 — PHP Remote File Inclusion  `INP16`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-234 — XSS Using Alternate Syntax  `SC04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-237 — Removing Important Client Functionality  `SC05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-239 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-242 — Exploiting Trust in Client  `AA04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-246 — XML Attribute Blowup  `INP22`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-247 — XSS Targeting URI Placeholders  `INP28`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-249 — SOAP Array Overflow  `INP34`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-251 — HTTP Request Smuggling  `INP37`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-252 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-254 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-263 — Format String Injection  `INP08`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-264 — LDAP Injection  `INP09`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-266 — Relative Path Traversal  `INP11`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-268 — Dictionary-based Password Attack  `CR03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-274 — Embedding Scripts within Scripts  `SC03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-275 — PHP Remote File Inclusion  `INP16`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-278 — XSS Using Alternate Syntax  `SC04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-281 — Removing Important Client Functionality  `SC05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-283 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-286 — Exploiting Trust in Client  `AA04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-290 — XML Attribute Blowup  `INP22`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-291 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-293 — SOAP Array Overflow  `INP34`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-295 — HTTP Request Smuggling  `INP37`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-296 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-298 — Server Side Include (SSI) Injection  `INP03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-307 — Format String Injection  `INP08`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-308 — LDAP Injection  `INP09`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-310 — Relative Path Traversal  `INP11`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-312 — Dictionary-based Password Attack  `CR03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-318 — Embedding Scripts within Scripts  `SC03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-319 — PHP Remote File Inclusion  `INP16`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-322 — XSS Using Alternate Syntax  `SC04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-325 — Removing Important Client Functionality  `SC05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-327 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-330 — Exploiting Trust in Client  `AA04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-334 — XML Attribute Blowup  `INP22`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-335 — XSS Targeting URI Placeholders  `INP28`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-337 — SOAP Array Overflow  `INP34`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-339 — HTTP Request Smuggling  `INP37`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-340 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-342 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-351 — Format String Injection  `INP08`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-352 — LDAP Injection  `INP09`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-354 — Relative Path Traversal  `INP11`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-356 — Dictionary-based Password Attack  `CR03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-362 — Embedding Scripts within Scripts  `SC03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-363 — PHP Remote File Inclusion  `INP16`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-366 — XSS Using Alternate Syntax  `SC04`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-369 — Removing Important Client Functionality  `SC05`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-371 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-374 — Exploiting Trust in Client  `AA04`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-378 — XML Attribute Blowup  `INP22`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-379 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-381 — SOAP Array Overflow  `INP34`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-383 — HTTP Request Smuggling  `INP37`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-384 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-386 — Direct Prompt Injection  `LLM01`

- **Element:** Ollama (local models) (sidecar)
- **Response:** accepted — Collected text reaches the model delimited and flattened, replies are JSON-schema validated, and the model has no tools, so an injected instruction cannot execute anything. It can still skew the assessment: a schema-valid risk level feeds alert_case_reason (pipeline.py, alerts/__init__.py) and can raise or suppress a risk-threshold alert. Residual risk accepted: the new-observables rule fires independently of the model, the evidence and rationale stay visible to the analyst, and model output is an aid, not a determination (README, Responsible use).
- **pytm mitigations:** Implement input content filtering and guardrails. Use prompt engineering techniques to make the system prompt more robust against injection. Apply output validation to detect and block manipulated responses. Monitor and log prompts for anomalous patterns.

#### F-387 — Jailbreaking and Safety Bypass  `LLM07`

- **Element:** Ollama (local models) (sidecar)
- **Response:** accepted — Same as LLM01: a jailbroken reply is either rejected by the schema or lands as a plausible-looking but wrong assessment that an analyst must review; it drives no action beyond the alert-threshold comparison.
- **pytm mitigations:** Implement layered defense with both system prompts and content filtering. Use output filtering to detect and block policy-violating responses. Regularly test with adversarial prompts and update defenses. Consider using classifier models to detect jailbreaking attempts.

#### F-388 — Sensitive Information Disclosure Through Output  `LLM08`

- **Element:** Ollama (local models) (sidecar)
- **Response:** accepted — A reply is consumed as data, never executed: the orchestrator's synthesis is JSON-schema validated and SocialOSINT's report is attached as an unverified note, and both are stored and rendered escaped under the console's CSP. What a reply can echo is the public footprint the prompt carried, which the evidence already holds; nothing filters personal-data patterns out of a summary before it is stored. Hardening: output redaction or DLP before a finding or note is persisted.
- **pytm mitigations:** Implement output filtering to detect and redact sensitive data patterns (PII, credentials, etc.). Use output encoding appropriate to the consumption context. Apply data loss prevention (DLP) controls on LLM outputs. Minimize the amount of sensitive data in the LLM's context.

#### F-389 — Server Side Include (SSI) Injection  `INP03`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-397 — Format String Injection  `INP08`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-398 — LDAP Injection  `INP09`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-400 — Relative Path Traversal  `INP11`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-402 — Dictionary-based Password Attack  `CR03`

- **Element:** MISP (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-408 — Embedding Scripts within Scripts  `SC03`

- **Element:** MISP (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-409 — PHP Remote File Inclusion  `INP16`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-411 — XSS Using Alternate Syntax  `SC04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-414 — Removing Important Client Functionality  `SC05`

- **Element:** MISP (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-416 — Exploitation of Trusted Credentials  `AA03`

- **Element:** MISP (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-419 — Exploiting Trust in Client  `AA04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-423 — XML Attribute Blowup  `INP22`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-424 — XSS Targeting URI Placeholders  `INP28`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-426 — SOAP Array Overflow  `INP34`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-428 — HTTP Request Smuggling  `INP37`

- **Element:** MISP (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-429 — Session Credential Falsification through Prediction  `AC16`

- **Element:** MISP (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-431 — Server Side Include (SSI) Injection  `INP03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-432 — Session Sidejacking  `CR01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-441 — Format String Injection  `INP08`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-442 — LDAP Injection  `INP09`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-444 — Relative Path Traversal  `INP11`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-450 — Embedding Scripts within Scripts  `SC03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-451 — PHP Remote File Inclusion  `INP16`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-455 — XSS Using Alternate Syntax  `SC04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-457 — Removing Important Client Functionality  `SC05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-459 — Exploitation of Trusted Credentials  `AA03`

- **Element:** OpenCTI platform (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-462 — Exploiting Trust in Client  `AA04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-466 — XML Attribute Blowup  `INP22`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-467 — XSS Targeting URI Placeholders  `INP28`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-469 — SOAP Array Overflow  `INP34`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-471 — HTTP Request Smuggling  `INP37`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-472 — Session Credential Falsification through Prediction  `AC16`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-474 — Reusing Session IDs (aka Session Replay) - ServerSide  `AC19`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-479 — Audit Log Manipulation  `DE04`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — OpenCTI's own audit trail lives in its backing stores and is the platform's.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-487 — Format String Injection  `INP08`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-488 — Client-side Injection-induced Buffer Overflow  `INP12`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** The client software should not install untrusted code from a non-authenticated server. The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers. Perform input validation for length of buffer inputs. Use a language or compiler that performs automatic bounds checking. Use an abstraction library to abstract away risky APIs. Not a complete solution. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Ensure all buffer uses are consistently bounds-checked. Use OS-level preventative functionality. Not a complete solution.

#### F-489 — Command Delimiters  `INP13`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Perform whitelist validation against a positive specification for command length, type, and parameters.Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running under a privileged accountImplementation: Perform input validation for all remote content.Implementation: Use type conversions such as JDBC prepared statements.

#### F-491 — Dictionary-based Password Attack  `CR03`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-493 — iFrame Overlay  `INP20`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Configuration: Disable iFrames in the Web browser.Operation: When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.Operation: If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.

#### F-495 — Privilege Escalation  `AC12`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-498 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-499 — Resource Injection  `INP25`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Ensure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-500 — Code Injection  `INP26`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Utilize strict type, character, and encoding enforcementEnsure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-502 — XSS Targeting URI Placeholders  `INP28`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-505 — Command Injection  `INP31`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary.Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter.Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.

#### F-506 — XML Injection  `INP32`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.

#### F-507 — Remote Code Inclusion  `INP33`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize attacks by input validation and sanitization of any user data that will be used by the target application to locate a remote file to be included.

#### F-508 — Leverage Alternate Encoding  `INP35`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input.

#### F-509 — Schema Poisoning  `AC15`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Schema handling inside oauth2-proxy and connector-misp is upstream's; the orchestrator validates everything it receives from either side.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-511 — Argument Injection  `INP41`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out all unauthorized commands and characters in the process.Design: Limit program privileges, so if metacharacters or other methods circumvent program input validation routines and shell access is attained then it is not running under a privileged account. chroot jails create a sandbox for the application to execute in, making it more difficult for an attacker to elevate privilege even in the case that a compromise has occurred.Implementation: Implement an audit log that is written to a separate host, in the event of a compromise the audit log may be able to provide evidence and details of the compromise.

#### F-512 — Reusing Session IDs (aka Session Replay) - ClientSide  `AC20`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-514 — Session Sidejacking  `CR01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback and hardcodes OAUTH2_PROXY_COOKIE_SECURE=false (no variable reads it): the session cookie is exposed to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front of the proxy and a Compose override that sets OAUTH2_PROXY_COOKIE_SECURE to true.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-519 — Communication Channel Manipulation  `CR06`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-522 — Unprotected Sensitive Data  `DR01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-523 — Credentials Disclosure  `AC23`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-524 — Session Sidejacking  `CR01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback and hardcodes OAUTH2_PROXY_COOKIE_SECURE=false (no variable reads it): the session cookie is exposed to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front of the proxy and a Compose override that sets OAUTH2_PROXY_COOKIE_SECURE to true.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-529 — Communication Channel Manipulation  `CR06`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-532 — Unprotected Sensitive Data  `DR01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-533 — Credentials Disclosure  `AC23`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-537 — Communication Channel Manipulation  `CR06`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-540 — Unprotected Sensitive Data  `DR01`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-541 — Credentials Disclosure  `AC23`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-545 — Communication Channel Manipulation  `CR06`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-548 — Unprotected Sensitive Data  `DR01`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-549 — Credentials Disclosure  `AC23`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-553 — Communication Channel Manipulation  `CR06`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-556 — Unprotected Sensitive Data  `DR01`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-557 — Credentials Disclosure  `AC23`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-561 — Communication Channel Manipulation  `CR06`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-566 — Communication Channel Manipulation  `CR06`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-569 — Unprotected Sensitive Data  `DR01`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-570 — Credentials Disclosure  `AC23`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-574 — Communication Channel Manipulation  `CR06`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-579 — Communication Channel Manipulation  `CR06`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-582 — Unprotected Sensitive Data  `DR01`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-586 — Communication Channel Manipulation  `CR06`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-591 — Communication Channel Manipulation  `CR06`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-594 — Unprotected Sensitive Data  `DR01`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-598 — Communication Channel Manipulation  `CR06`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-601 — Unprotected Sensitive Data  `DR01`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-605 — Communication Channel Manipulation  `CR06`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-607 — Credentials Disclosure  `AC23`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-611 — Communication Channel Manipulation  `CR06`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-614 — Unprotected Sensitive Data  `DR01`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-618 — Communication Channel Manipulation  `CR06`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-621 — Unprotected Sensitive Data  `DR01`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-625 — Communication Channel Manipulation  `CR06`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-627 — Credentials Disclosure  `AC23`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-631 — Communication Channel Manipulation  `CR06`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-633 — Credentials Disclosure  `AC23`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-637 — Communication Channel Manipulation  `CR06`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-639 — Credentials Disclosure  `AC23`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-643 — Communication Channel Manipulation  `CR06`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-646 — Unprotected Sensitive Data  `DR01`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-650 — Communication Channel Manipulation  `CR06`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-655 — Communication Channel Manipulation  `CR06`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-658 — Unprotected Sensitive Data  `DR01`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-662 — Communication Channel Manipulation  `CR06`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-667 — Communication Channel Manipulation  `CR06`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-670 — Unprotected Sensitive Data  `DR01`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-674 — Communication Channel Manipulation  `CR06`

- **Element:** Local model inference (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-677 — Unprotected Sensitive Data  `DR01`

- **Element:** Local model inference (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-681 — Communication Channel Manipulation  `CR06`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-683 — Credentials Disclosure  `AC23`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-687 — Communication Channel Manipulation  `CR06`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-690 — Unprotected Sensitive Data  `DR01`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-694 — Communication Channel Manipulation  `CR06`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-697 — Unprotected Sensitive Data  `DR01`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-701 — Communication Channel Manipulation  `CR06`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-706 — Communication Channel Manipulation  `CR06`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-709 — Unprotected Sensitive Data  `DR01`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-710 — Credentials Disclosure  `AC23`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-714 — Communication Channel Manipulation  `CR06`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-717 — Unprotected Sensitive Data  `DR01`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-721 — Communication Channel Manipulation  `CR06`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-724 — Unprotected Sensitive Data  `DR01`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-725 — Credentials Disclosure  `AC23`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-729 — Communication Channel Manipulation  `CR06`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-732 — Unprotected Sensitive Data  `DR01`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-733 — Credentials Disclosure  `AC23`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-737 — Communication Channel Manipulation  `CR06`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-740 — Unprotected Sensitive Data  `DR01`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-744 — Communication Channel Manipulation  `CR06`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-746 — Credentials Disclosure  `AC23`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-750 — Communication Channel Manipulation  `CR06`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-753 — Unprotected Sensitive Data  `DR01`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-754 — Credentials Disclosure  `AC23`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-758 — Communication Channel Manipulation  `CR06`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-760 — Credentials Disclosure  `AC23`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-764 — Communication Channel Manipulation  `CR06`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Internet hops that carry credentials or evidence are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-766 — Credentials Disclosure  `AC23`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

### Severity: Medium (347)

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

#### F-72 — XSS Targeting Error Pages  `DS04`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-75 — Manipulate Registry Information  `AC08`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-77 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-79 — Functionality Misuse  `AC09`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-82 — XML External Entities Blowup  `INP19`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-83 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-84 — DTD Injection  `INP21`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-87 — XSS Using Doubled Characters  `INP29`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-89 — HTTP Response Smuggling  `INP36`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-94 — Authentication Abuse/ByPass  `AA01`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-95 — Double Encoding  `DE02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-96 — Privilege Abuse  `AC01`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-98 — Flooding  `DO01`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-99 — Excessive Allocation  `DO02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-103 — Input Data Manipulation  `INP14`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-104 — Principal Spoof  `AA02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-108 — Hijacking a privileged process  `AC13`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-113 — XSS Targeting HTML Attributes  `INP27`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list all input including that which is not expected to have any scripting content.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-115 — XSS Using Doubled Characters  `INP29`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-116 — XSS Using Invalid Characters  `INP30`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be included in any subsequent web pages or back end operations.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-128 — Authentication Abuse/ByPass  `AA01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-129 — Excavation  `DS01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-130 — Double Encoding  `DE02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-131 — Privilege Abuse  `AC01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-132 — Flooding  `DO01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-134 — Excessive Allocation  `DO02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-137 — Parameter Injection  `INP10`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-139 — Input Data Manipulation  `INP14`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-144 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-147 — Principal Spoof  `AA02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-148 — Session Credential Falsification through Forging  `CR04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-149 — XSS Targeting Error Pages  `DS04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-152 — Manipulate Registry Information  `AC08`

- **Element:** Keycloak (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-154 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Keycloak (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-156 — Functionality Misuse  `AC09`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-159 — XML External Entities Blowup  `INP19`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-160 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-161 — DTD Injection  `INP21`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-164 — XSS Using Doubled Characters  `INP29`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-166 — HTTP Response Smuggling  `INP36`

- **Element:** Keycloak (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-172 — Authentication Abuse/ByPass  `AA01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests) under the assumption that ORCHESTRATOR_API_KEY is set; /health and /metrics are intentionally open; the console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-174 — Flooding  `DO01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** accepted — No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-175 — Excessive Allocation  `DO02`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** accepted — Per-run budgets cap the collectors and the models (TAVILY_MAX_CALLS_PER_RUN, LLM_QUALIFY_MAX_ITEMS, LLM_MAX_TOKENS), but POST /bundles reads the whole body with request.json() before validating it and no middleware caps uploads, so an authenticated producer can exhaust memory with one request. Hardening: a body-size limit at the reverse proxy or TLS terminator in front of :8000.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-176 — Principal Spoof  `AA02`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds an authenticated person (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-178 — Hijacking a privileged process  `AC13`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-184 — Authentication Abuse/ByPass  `AA01`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests) under the assumption that ORCHESTRATOR_API_KEY is set; /health and /metrics are intentionally open; the console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-185 — Flooding  `DO01`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** accepted — No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-186 — Excessive Allocation  `DO02`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** accepted — Per-run budgets cap the collectors and the models (TAVILY_MAX_CALLS_PER_RUN, LLM_QUALIFY_MAX_ITEMS, LLM_MAX_TOKENS), but POST /bundles reads the whole body with request.json() before validating it and no middleware caps uploads, so an authenticated producer can exhaust memory with one request. Hardening: a body-size limit at the reverse proxy or TLS terminator in front of :8000.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-187 — Principal Spoof  `AA02`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds an authenticated person (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-189 — Hijacking a privileged process  `AC13`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-193 — Privilege Abuse  `AC01`

- **Element:** SQLite run store (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-194 — Excessive Allocation  `DO02`

- **Element:** SQLite run store (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-197 — Privilege Abuse  `AC01`

- **Element:** targets.yaml (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-198 — Excessive Allocation  `DO02`

- **Element:** targets.yaml (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-201 — Privilege Abuse  `AC01`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-202 — Excessive Allocation  `DO02`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-205 — Privilege Abuse  `AC01`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-206 — Shared Data Manipulation  `AC02`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — The Amass asset database is shared between the engine and the orchestrator on one volume of the trusted host (ADR-005); oam_subs output is parsed as untrusted text.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. Use HTTPS/SSL for communication.

#### F-207 — Excessive Allocation  `DO02`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-212 — Authentication Abuse/ByPass  `AA01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-213 — Excavation  `DS01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-214 — Double Encoding  `DE02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-215 — Privilege Abuse  `AC01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-216 — Flooding  `DO01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-218 — Excessive Allocation  `DO02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-221 — Parameter Injection  `INP10`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-223 — Input Data Manipulation  `INP14`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-229 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-232 — Principal Spoof  `AA02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-233 — XSS Targeting Error Pages  `DS04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-236 — Manipulate Registry Information  `AC08`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-238 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-240 — Functionality Misuse  `AC09`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-243 — XML External Entities Blowup  `INP19`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-244 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-245 — DTD Injection  `INP21`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-248 — XSS Using Doubled Characters  `INP29`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-250 — HTTP Response Smuggling  `INP36`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-256 — Authentication Abuse/ByPass  `AA01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-257 — Excavation  `DS01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-258 — Double Encoding  `DE02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-259 — Privilege Abuse  `AC01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-260 — Flooding  `DO01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-262 — Excessive Allocation  `DO02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-265 — Parameter Injection  `INP10`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-267 — Input Data Manipulation  `INP14`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-273 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-276 — Principal Spoof  `AA02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-277 — XSS Targeting Error Pages  `DS04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-280 — Manipulate Registry Information  `AC08`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-282 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-284 — Functionality Misuse  `AC09`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-287 — XML External Entities Blowup  `INP19`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-288 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-289 — DTD Injection  `INP21`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-292 — XSS Using Doubled Characters  `INP29`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-294 — HTTP Response Smuggling  `INP36`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-300 — Authentication Abuse/ByPass  `AA01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-301 — Excavation  `DS01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-302 — Double Encoding  `DE02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-303 — Privilege Abuse  `AC01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-304 — Flooding  `DO01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-306 — Excessive Allocation  `DO02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-309 — Parameter Injection  `INP10`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-311 — Input Data Manipulation  `INP14`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-317 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-320 — Principal Spoof  `AA02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-321 — XSS Targeting Error Pages  `DS04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-324 — Manipulate Registry Information  `AC08`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-326 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-328 — Functionality Misuse  `AC09`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-331 — XML External Entities Blowup  `INP19`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-332 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-333 — DTD Injection  `INP21`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-336 — XSS Using Doubled Characters  `INP29`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-338 — HTTP Response Smuggling  `INP36`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-344 — Authentication Abuse/ByPass  `AA01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-345 — Excavation  `DS01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-346 — Double Encoding  `DE02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-347 — Privilege Abuse  `AC01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-348 — Flooding  `DO01`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-350 — Excessive Allocation  `DO02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-353 — Parameter Injection  `INP10`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-355 — Input Data Manipulation  `INP14`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-361 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-364 — Principal Spoof  `AA02`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-365 — XSS Targeting Error Pages  `DS04`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-368 — Manipulate Registry Information  `AC08`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-370 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-372 — Functionality Misuse  `AC09`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-375 — XML External Entities Blowup  `INP19`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-376 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-377 — DTD Injection  `INP21`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-380 — XSS Using Doubled Characters  `INP29`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-382 — HTTP Response Smuggling  `INP36`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-391 — Excavation  `DS01`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-392 — Double Encoding  `DE02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-393 — Privilege Abuse  `AC01`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-394 — Flooding  `DO01`

- **Element:** MISP (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-396 — Excessive Allocation  `DO02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-399 — Parameter Injection  `INP10`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-401 — Input Data Manipulation  `INP14`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-407 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-410 — XSS Targeting Error Pages  `DS04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-413 — Manipulate Registry Information  `AC08`

- **Element:** MISP (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-415 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** MISP (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-417 — Functionality Misuse  `AC09`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-420 — XML External Entities Blowup  `INP19`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-421 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** MISP (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-422 — DTD Injection  `INP21`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-425 — XSS Using Doubled Characters  `INP29`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-427 — HTTP Response Smuggling  `INP36`

- **Element:** MISP (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-434 — Authentication Abuse/ByPass  `AA01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-435 — Excavation  `DS01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-436 — Double Encoding  `DE02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-437 — Privilege Abuse  `AC01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-438 — Flooding  `DO01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-440 — Excessive Allocation  `DO02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-443 — Parameter Injection  `INP10`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-445 — Input Data Manipulation  `INP14`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-452 — Principal Spoof  `AA02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-453 — Session Credential Falsification through Forging  `CR04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-454 — XSS Targeting Error Pages  `DS04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-458 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-460 — Functionality Misuse  `AC09`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-463 — XML External Entities Blowup  `INP19`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-464 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-465 — DTD Injection  `INP21`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-468 — XSS Using Doubled Characters  `INP29`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-470 — HTTP Response Smuggling  `INP36`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-475 — Privilege Abuse  `AC01`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-476 — Shared Data Manipulation  `AC02`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — OpenCTI's backing stores (Elasticsearch, MinIO, RabbitMQ, Redis) are owned and hardened by the OpenCTI platform deployment.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. Use HTTPS/SSL for communication.

#### F-477 — Excessive Allocation  `DO02`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-481 — Authentication Abuse/ByPass  `AA01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-482 — Double Encoding  `DE02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-483 — Privilege Abuse  `AC01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-485 — Flooding  `DO01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-486 — Excessive Allocation  `DO02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-490 — Input Data Manipulation  `INP14`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-492 — Principal Spoof  `AA02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-496 — Hijacking a privileged process  `AC13`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-501 — XSS Targeting HTML Attributes  `INP27`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list all input including that which is not expected to have any scripting content.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-503 — XSS Using Doubled Characters  `INP29`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-504 — XSS Using Invalid Characters  `INP30`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be included in any subsequent web pages or back end operations.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-516 — Interception  `DE01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-517 — Content Spoofing  `AC05`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-518 — Sniffing Attacks  `DE03`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-520 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-526 — Interception  `DE01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-527 — Content Spoofing  `AC05`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-528 — Sniffing Attacks  `DE03`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-530 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-534 — Interception  `DE01`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-535 — Content Spoofing  `AC05`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-536 — Sniffing Attacks  `DE03`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-538 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-542 — Interception  `DE01`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-543 — Content Spoofing  `AC05`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-544 — Sniffing Attacks  `DE03`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-546 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-550 — Interception  `DE01`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-551 — Content Spoofing  `AC05`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-552 — Sniffing Attacks  `DE03`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-554 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-558 — Interception  `DE01`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-559 — Content Spoofing  `AC05`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-560 — Sniffing Attacks  `DE03`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-562 — Client-Server Protocol Manipulation  `CR08`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-563 — Interception  `DE01`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-564 — Content Spoofing  `AC05`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-565 — Sniffing Attacks  `DE03`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-567 — Client-Server Protocol Manipulation  `CR08`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-571 — Interception  `DE01`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-572 — Content Spoofing  `AC05`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-573 — Sniffing Attacks  `DE03`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-575 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-576 — Interception  `DE01`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-577 — Content Spoofing  `AC05`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-578 — Sniffing Attacks  `DE03`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-580 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Scan control & results (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-583 — Interception  `DE01`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-584 — Content Spoofing  `AC05`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-585 — Sniffing Attacks  `DE03`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-587 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-588 — Interception  `DE01`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-589 — Content Spoofing  `AC05`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-590 — Sniffing Attacks  `DE03`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-592 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-595 — Interception  `DE01`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-596 — Content Spoofing  `AC05`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-597 — Sniffing Attacks  `DE03`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-599 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-602 — Interception  `DE01`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-603 — Content Spoofing  `AC05`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-604 — Sniffing Attacks  `DE03`

- **Element:** Passive data-source queries (datasources.yaml keys) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-608 — Interception  `DE01`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-609 — Content Spoofing  `AC05`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-610 — Sniffing Attacks  `DE03`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-612 — Client-Server Protocol Manipulation  `CR08`

- **Element:** DNS resolution and active probes (zone transfers, certificate grabs when enabled) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-615 — Interception  `DE01`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-616 — Content Spoofing  `AC05`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-617 — Sniffing Attacks  `DE03`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-619 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-622 — Interception  `DE01`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-623 — Content Spoofing  `AC05`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-624 — Sniffing Attacks  `DE03`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-628 — Interception  `DE01`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-629 — Content Spoofing  `AC05`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-630 — Sniffing Attacks  `DE03`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-634 — Interception  `DE01`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-635 — Content Spoofing  `AC05`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-636 — Sniffing Attacks  `DE03`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-640 — Interception  `DE01`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-641 — Content Spoofing  `AC05`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-642 — Sniffing Attacks  `DE03`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-644 — Client-Server Protocol Manipulation  `CR08`

- **Element:** DNS, WHOIS and plaintext probes (sfp_dnsresolve, sfp_whois) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-647 — Interception  `DE01`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-648 — Content Spoofing  `AC05`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-649 — Sniffing Attacks  `DE03`

- **Element:** TLS certificate and HTTPS fetches (sfp_sslcert) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-652 — Interception  `DE01`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-653 — Content Spoofing  `AC05`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-654 — Sniffing Attacks  `DE03`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-656 — Client-Server Protocol Manipulation  `CR08`

- **Element:** DNS and WHOIS pivots (OpenOSINT) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-659 — Interception  `DE01`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-660 — Content Spoofing  `AC05`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-661 — Sniffing Attacks  `DE03`

- **Element:** HTTPS source lookups (OpenOSINT) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-664 — Interception  `DE01`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-665 — Content Spoofing  `AC05`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-666 — Sniffing Attacks  `DE03`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-668 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Qualification & synthesis prompts (local HTTP API) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-671 — Interception  `DE01`

- **Element:** Local model inference (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-672 — Content Spoofing  `AC05`

- **Element:** Local model inference (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-673 — Sniffing Attacks  `DE03`

- **Element:** Local model inference (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-675 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Local model inference (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-678 — Interception  `DE01`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-679 — Content Spoofing  `AC05`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-680 — Sniffing Attacks  `DE03`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-684 — Interception  `DE01`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-685 — Content Spoofing  `AC05`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-686 — Sniffing Attacks  `DE03`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-688 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-691 — Interception  `DE01`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-692 — Content Spoofing  `AC05`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-693 — Sniffing Attacks  `DE03`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-695 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-698 — Interception  `DE01`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-699 — Content Spoofing  `AC05`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-700 — Sniffing Attacks  `DE03`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-702 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read target inventory (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-703 — Interception  `DE01`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-704 — Content Spoofing  `AC05`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-705 — Sniffing Attacks  `DE03`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-707 — Client-Server Protocol Manipulation  `CR08`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-711 — Interception  `DE01`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-712 — Content Spoofing  `AC05`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-713 — Sniffing Attacks  `DE03`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-715 — Client-Server Protocol Manipulation  `CR08`

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

#### F-726 — Interception  `DE01`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-727 — Content Spoofing  `AC05`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-728 — Sniffing Attacks  `DE03`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-730 — Client-Server Protocol Manipulation  `CR08`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-734 — Interception  `DE01`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-735 — Content Spoofing  `AC05`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-736 — Sniffing Attacks  `DE03`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-738 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-741 — Interception  `DE01`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-742 — Content Spoofing  `AC05`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-743 — Sniffing Attacks  `DE03`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-747 — Interception  `DE01`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-748 — Content Spoofing  `AC05`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-749 — Sniffing Attacks  `DE03`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-751 — Client-Server Protocol Manipulation  `CR08`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Use strong authentication protocols.

#### F-755 — Interception  `DE01`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-756 — Content Spoofing  `AC05`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-757 — Sniffing Attacks  `DE03`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-761 — Interception  `DE01`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; what leaves the host with a credential or evidence inside is TLS. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-762 — Content Spoofing  `AC05`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-763 — Sniffing Attacks  `DE03`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing a host-internal hop requires host compromise, which is out of the modelled scope. The collectors' own discovery traffic (SpiderFoot's and Amass's DNS, WHOIS and probes of the target's surface) is plaintext by nature: it carries the target name and what the public already serves, never a credential, and its answers are treated as untrusted input.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

### Severity: Low (32)

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

#### F-74 — Encryption Brute Forcing  `CR05`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-80 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-142 — Web Application Fingerprinting  `HA03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-151 — Encryption Brute Forcing  `CR05`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-157 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-195 — Encryption Brute Forcing  `CR05`

- **Element:** SQLite run store (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-199 — Encryption Brute Forcing  `CR05`

- **Element:** targets.yaml (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-203 — Encryption Brute Forcing  `CR05`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-208 — Encryption Brute Forcing  `CR05`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-227 — Web Application Fingerprinting  `HA03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-235 — Encryption Brute Forcing  `CR05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-241 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-271 — Web Application Fingerprinting  `HA03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-279 — Encryption Brute Forcing  `CR05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-285 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-315 — Web Application Fingerprinting  `HA03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-323 — Encryption Brute Forcing  `CR05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-329 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-359 — Web Application Fingerprinting  `HA03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-367 — Encryption Brute Forcing  `CR05`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-373 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-405 — Web Application Fingerprinting  `HA03`

- **Element:** MISP (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-412 — Encryption Brute Forcing  `CR05`

- **Element:** MISP (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-418 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-448 — Web Application Fingerprinting  `HA03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-456 — Encryption Brute Forcing  `CR05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-461 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-478 — Encryption Brute Forcing  `CR05`

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

#### F-140 — Footprinting  `DS03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-225 — Footprinting  `DS03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-269 — Footprinting  `DS03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-313 — Footprinting  `DS03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-357 — Footprinting  `DS03`

- **Element:** Ollama HTTP API (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-403 — Footprinting  `DS03`

- **Element:** MISP (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-446 — Footprinting  `DS03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.
