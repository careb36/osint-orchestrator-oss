# Threat model — OSINT Orchestrator (OWASP pytm, threat library 114 threats)

Modular monolith (ADR-001): one FastAPI process with an in-process APScheduler and a SQLite store drives OSINT collectors, qualifies evidence with an LLM, normalises findings to STIX 2.1 (ADR-002), ingests them into OpenCTI (ADR-003/008), seals a signed report chain per run (ADR-007) and dispatches alerts by webhook and e-mail. Access uses static API keys and a single instance (ADR-005), with an optional OIDC proxy perimeter (ADR-006) and an external STIX intake (ADR-011). Operator prose is Spanish, code English (ADR-004).

## Assumptions

- Single-instance deployment on a trusted Docker host; loopback-published ports are reachable only from that host.
- The Docker host and the compose network are operated by the same team as the orchestrator.
- ORCHESTRATOR_API_KEY is set. require_api_key is a no-op with an empty key (open mode, documented in ADR-005 and ADR-006); that mode is out of this model's scope.
- The shipped docker-compose.auth.yml terminates no TLS: oauth2-proxy listens on plain HTTP on loopback with AUTH_PROXY_COOKIE_SECURE=false. A TLS terminator in front of it is a production hardening step, modelled as absent.
- Alert channels are modelled with their defaults: SMTP with STARTTLS (ALERT_SMTP_STARTTLS=true) and the webhook over the operator's URL with the optional HMAC signature (ALERT_WEBHOOK_SECRET) unset.
- Collectors only query targets authorised in targets.yaml (operator attestation per target).
- OpenCTI, MISP, Amass, SocialOSINT and the OIDC overlay are optional deployments; the model covers them when enabled.
- ORCHESTRATOR_SECRET_KEY is a private, randomly generated value. The default insecure-dev-key only earns a startup warning (auth.py); with it, or with an empty key, anyone can forge a manifest, and the integrity claims of this model do not hold.

## Element classes

A response is written per class: the same threat means something different on the orchestrator, on an unauthenticated sidecar, on a vendor service, on a store or on a flow.

- **orchestrator**: Orchestrator API (FastAPI + APScheduler), APScheduler cron jobs
- **sidecar**: SpiderFoot, Amass v5 engine, SocialOSINT sidecar, Ollama (local models)
- **vendor**: Tavily search API, Cloud LLM provider, SMTP relay (alert e-mail), Alert webhook receiver, oauth2-proxy, Keycloak, MISP, OpenCTI platform, OpenCTI backing stores, connector-misp
- **store**: SQLite run store, targets.yaml, daily_reports (sealed runs), Amass asset database (shared volume)
- **flow**: every dataflow, named by what it carries

## Findings: 678 across 84 distinct threats

Every finding carries a triage response:

- **accepted**: 367 finding(s)
- **mitigated**: 21 finding(s)
- **transferred**: 290 finding(s)

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
| AC05 Content Spoofing | Medium | flow | accepted | Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06). |
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
| CR01 Session Sidejacking | High | flow | accepted | The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback with AUTH_PROXY_COOKIE_SECURE=false: the session cookie is exposed to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front of the proxy and AUTH_PROXY_COOKIE_SECURE=true. |
| CR01 Session Sidejacking | High | vendor | transferred | Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens. |
| CR02 Cross Site Tracing | Very High | flow | accepted | FastAPI answers TRACE with 405 and the console ships no inline script that could read reflected headers; the plaintext proxied hop itself is the DS06 decision (shipped overlay without TLS). Hardening: TLS terminator that drops TRACE. |
| CR03 Dictionary-based Password Attack | High | sidecar | accepted | SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services. |
| CR03 Dictionary-based Password Attack | High | vendor | transferred | Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay. |
| CR04 Session Credential Falsification through Forging | Medium | vendor | transferred | Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens. |
| CR05 Encryption Brute Forcing | Low | sidecar | accepted | Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material. |
| CR05 Encryption Brute Forcing | Low | store | accepted | Nothing is encrypted at rest to brute-force (DR01). |
| CR05 Encryption Brute Forcing | Low | vendor | transferred | Cryptography inside vendor services is the vendor's. |
| CR06 Communication Channel Manipulation | High | flow | accepted | Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06. |
| CR08 Client-Server Protocol Manipulation | Medium | flow | accepted | The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06). |
| DE01 Interception | Medium | flow | accepted | Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS. |
| DE02 Double Encoding | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DE02 Double Encoding | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DE03 Sniffing Attacks | Medium | flow | accepted | Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope. |
| DE04 Audit Log Manipulation | High | store | accepted | Run rows are outside the manifest chain: /targets/{id}/chain/verify checks the manifest hash, signature, chain link and artefact files (evidence.py), not a row's status, collectors or timestamps, so an edit to those fields with the manifest intact goes undetected. Hardening: database file permissions, backups and disk encryption. |
| DE04 Audit Log Manipulation | High | vendor | transferred | OpenCTI's own audit trail lives in its backing stores and is the platform's. |
| DO01 Flooding | Medium | orchestrator | accepted | No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator. |
| DO01 Flooding | Medium | sidecar | accepted | The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps. |
| DO01 Flooding | Medium | vendor | transferred | Rate limiting of vendor services is the vendor's. |
| DO02 Excessive Allocation | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DO02 Excessive Allocation | Medium | store | accepted | Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes. |
| DO02 Excessive Allocation | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DR01 Unprotected Sensitive Data | High | flow | accepted | Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services. |
| DS01 Excavation | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DS01 Excavation | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DS03 Footprinting | Very Low | sidecar | accepted | Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments. |
| DS03 Footprinting | Very Low | vendor | transferred | Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment. |
| DS04 XSS Targeting Error Pages | Medium | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| DS04 XSS Targeting Error Pages | Medium | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| DS06 Data Leak | Very High | flow | accepted | Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption. |
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
| LLM07 Jailbreaking and Safety Bypass | High | sidecar | accepted | Same as LLM01: a jailbroken reply is either rejected by the schema or lands as a plausible-looking but wrong assessment that an analyst must review; it drives no action beyond the alert-threshold comparison. |
| LLM07 Jailbreaking and Safety Bypass | High | vendor | accepted | Same as LLM01: a jailbroken reply is either rejected by the schema or lands as a plausible-looking but wrong assessment that an analyst must review; it drives no action beyond the alert-threshold comparison. |
| SC02 XSS Targeting Non-Script Elements | Very High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| SC02 XSS Targeting Non-Script Elements | Very High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| SC03 Embedding Scripts within Scripts | High | sidecar | accepted | The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only. |
| SC03 Embedding Scripts within Scripts | High | vendor | transferred | The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's. |
| SC04 XSS Using Alternate Syntax | High | sidecar | accepted | Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current. |
| SC04 XSS Using Alternate Syntax | High | vendor | transferred | Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves. |
| SC05 Removing Important Client Functionality | High | sidecar | accepted | No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only. |
| SC05 Removing Important Client Functionality | High | vendor | transferred | Client-side functionality of vendor UIs is the vendor's. |

## Full findings

### Severity: Very High (86)

#### F-2 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-7 — Path Traversal  `HA01`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-16 — Using Malicious Files  `AC06`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-18 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-42 — Session Hijacking - ServerSide  `AC17`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-46 — Command Line Execution through SQL Injection  `INP05`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-51 — Path Traversal  `HA01`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-60 — Using Malicious Files  `AC06`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-62 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-86 — Session Hijacking - ServerSide  `AC17`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-87 — Overflow Buffers  `INP02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-91 — Buffer Manipulation  `INP07`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** To help protect an application from buffer manipulation attacks, a number of potential mitigations can be leveraged. Before starting the development of the application, consider using a code language (e.g., Java) or compiler that limits the ability of developers to act beyond the bounds of a buffer. If the chosen language is susceptible to buffer related issues (e.g., C) then consider using secure functions instead of those vulnerable to buffer manipulations. If a potentially dangerous function must be used, make sure that proper boundary checking is performed. Additionally, there are often a number of compiler-based mechanisms (e.g., StackGuard, ProPolice and the Microsoft Visual Studio /GS flag) that can help identify and protect against potential buffer issues. Finally, there may be operating system level preventative functionality that can be applied.

#### F-100 — File Content Injection  `INP23`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Validate all input for content including files. Ensure that if files and remote content must be accepted that once accepted, they are placed in a sandbox type location so that lower assurance clients cannot write up to higher assurance processes (like Web server processes for example)Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.Implementation: Virus scanning on hostImplementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.

#### F-103 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-116 — Session Hijacking - ClientSide  `AC18`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-121 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-127 — Path Traversal  `HA01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-135 — Using Malicious Files  `AC06`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-137 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-163 — Session Hijacking - ServerSide  `AC17`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-165 — Overflow Buffers  `INP02`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS) and LLM_MAX_OBSERVABLES_IN_PROMPT.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-172 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — The pipeline isolates every step (collect, qualify, normalise, synthesise, seal, alert): a raised error fails the run, never a privileged transaction; the process runs as uid 1000 with no setuid paths (Dockerfile).
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-175 — Cross Site Request Forgery  `AC21`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no ambient credential to forge cross-site; the console CSP sets form-action 'none'; the scheduler has no HTTP surface. The OIDC overlay adds oauth2-proxy's CSRF token.
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-176 — Overflow Buffers  `INP02`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS) and LLM_MAX_OBSERVABLES_IN_PROMPT.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-184 — Cross Site Request Forgery  `AC21`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no ambient credential to forge cross-site; the console CSP sets form-action 'none'; the scheduler has no HTTP surface. The OIDC overlay adds oauth2-proxy's CSRF token.
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-203 — Command Line Execution through SQL Injection  `INP05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-209 — Path Traversal  `HA01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-218 — Using Malicious Files  `AC06`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-220 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-245 — Session Hijacking - ServerSide  `AC17`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-247 — Command Line Execution through SQL Injection  `INP05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-253 — Path Traversal  `HA01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-262 — Using Malicious Files  `AC06`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-264 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-289 — Session Hijacking - ServerSide  `AC17`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-291 — Command Line Execution through SQL Injection  `INP05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-297 — Path Traversal  `HA01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-306 — Using Malicious Files  `AC06`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator never executes what a sidecar produces: SpiderFoot, Amass and SocialOSINT output is parsed into CollectorResult inside the collector module (docs/architecture.md). The sidecars' own file handling is upstream code running loopback-only from pinned images. Hardening: read-only root filesystems and dropped capabilities for the sidecars.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-308 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-333 — Session Hijacking - ServerSide  `AC17`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-337 — Command Line Execution through SQL Injection  `INP05`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-342 — Path Traversal  `HA01`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-351 — Using Malicious Files  `AC06`

- **Element:** MISP (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-353 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-377 — Session Hijacking - ServerSide  `AC17`

- **Element:** MISP (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-380 — Command Line Execution through SQL Injection  `INP05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).

#### F-386 — Path Traversal  `HA01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.

#### F-394 — Using Malicious Files  `AC06`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Keycloak, MISP, Tavily and the SMTP relay own their file-handling surface; the orchestrator uploads no files to them and renders nothing they serve.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-396 — XSS Targeting Non-Script Elements  `SC02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

#### F-420 — Session Hijacking - ServerSide  `AC17`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-427 — Overflow Buffers  `INP02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-431 — Buffer Manipulation  `INP07`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** To help protect an application from buffer manipulation attacks, a number of potential mitigations can be leveraged. Before starting the development of the application, consider using a code language (e.g., Java) or compiler that limits the ability of developers to act beyond the bounds of a buffer. If the chosen language is susceptible to buffer related issues (e.g., C) then consider using secure functions instead of those vulnerable to buffer manipulations. If a potentially dangerous function must be used, make sure that proper boundary checking is performed. Additionally, there are often a number of compiler-based mechanisms (e.g., StackGuard, ProPolice and the Microsoft Visual Studio /GS flag) that can help identify and protect against potential buffer issues. Finally, there may be operating system level preventative functionality that can be applied.

#### F-441 — File Content Injection  `INP23`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Validate all input for content including files. Ensure that if files and remote content must be accepted that once accepted, they are placed in a sandbox type location so that lower assurance clients cannot write up to higher assurance processes (like Web server processes for example)Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.Implementation: Virus scanning on hostImplementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.

#### F-444 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-457 — Session Hijacking - ClientSide  `AC18`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-460 — Cross Site Request Forgery  `AC21`

- **Element:** connector-misp (vendor)
- **Response:** transferred — connector-misp has no browser-facing surface; CSRF on vendor UIs is the vendor's (oauth2-proxy implements its own CSRF token).
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-462 — Cross Site Tracing  `CR02`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — FastAPI answers TRACE with 405 and the console ships no inline script that could read reflected headers; the plaintext proxied hop itself is the DS06 decision (shipped overlay without TLS). Hardening: TLS terminator that drops TRACE.
- **pytm mitigations:** Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.

#### F-468 — Data Leak  `DS06`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-472 — Cross Site Tracing  `CR02`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — FastAPI answers TRACE with 405 and the console ships no inline script that could read reflected headers; the plaintext proxied hop itself is the DS06 decision (shipped overlay without TLS). Hardening: TLS terminator that drops TRACE.
- **pytm mitigations:** Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.

#### F-478 — Data Leak  `DS06`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-486 — Data Leak  `DS06`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-494 — Data Leak  `DS06`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-502 — Data Leak  `DS06`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-515 — Data Leak  `DS06`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-528 — Data Leak  `DS06`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-540 — Data Leak  `DS06`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-547 — Data Leak  `DS06`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-554 — Data Leak  `DS06`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-560 — Data Leak  `DS06`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-566 — Data Leak  `DS06`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-572 — Data Leak  `DS06`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-578 — Data Leak  `DS06`

- **Element:** Active reconnaissance (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-583 — Data Leak  `DS06`

- **Element:** Passive collection (OpenOSINT) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-589 — Data Leak  `DS06`

- **Element:** Qualification & synthesis prompts (local) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-595 — Data Leak  `DS06`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-602 — Data Leak  `DS06`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-609 — Data Leak  `DS06`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-621 — Data Leak  `DS06`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-629 — Data Leak  `DS06`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-636 — Data Leak  `DS06`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-644 — Data Leak  `DS06`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-652 — Data Leak  `DS06`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-658 — Data Leak  `DS06`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-665 — Data Leak  `DS06`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-672 — Data Leak  `DS06`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-677 — Data Leak  `DS06`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Flows that leave the host use TLS 1.2+ (Tavily, cloud LLM, public web, MISP poll, SMTP with STARTTLS, webhook over HTTPS). Host-internal hops are plaintext by decision ADR-005: loopback console/API, the compose bridge to sidecars, Ollama, OpenCTI, Keycloak, SQLite and files; the shipped OIDC overlay terminates no TLS, so the operator session is a host-local plaintext hop too. Hardening for shared infrastructure: a TLS terminator in front of :8000/:8002, TLS between services, disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

### Severity: High (248)

#### F-1 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-9 — Format String Injection  `INP08`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-10 — LDAP Injection  `INP09`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-12 — Relative Path Traversal  `INP11`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-14 — Dictionary-based Password Attack  `CR03`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-20 — Embedding Scripts within Scripts  `SC03`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-21 — PHP Remote File Inclusion  `INP16`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-23 — XSS Using Alternate Syntax  `SC04`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-26 — Removing Important Client Functionality  `SC05`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-28 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Tavily search API (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-31 — Exploiting Trust in Client  `AA04`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-35 — XML Attribute Blowup  `INP22`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-36 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-38 — SOAP Array Overflow  `INP34`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-40 — HTTP Request Smuggling  `INP37`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-41 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-43 — Direct Prompt Injection  `LLM01`

- **Element:** Cloud LLM provider (vendor)
- **Response:** accepted — Collected text reaches the model delimited and flattened, replies are JSON-schema validated, and the model has no tools, so an injected instruction cannot execute anything. It can still skew the assessment: a schema-valid risk level feeds alert_case_reason (pipeline.py, alerts/__init__.py) and can raise or suppress a risk-threshold alert. Residual risk accepted: the new-observables rule fires independently of the model, the evidence and rationale stay visible to the analyst, and model output is an aid, not a determination (README, Responsible use).
- **pytm mitigations:** Implement input content filtering and guardrails. Use prompt engineering techniques to make the system prompt more robust against injection. Apply output validation to detect and block manipulated responses. Monitor and log prompts for anomalous patterns.

#### F-44 — Jailbreaking and Safety Bypass  `LLM07`

- **Element:** Cloud LLM provider (vendor)
- **Response:** accepted — Same as LLM01: a jailbroken reply is either rejected by the schema or lands as a plausible-looking but wrong assessment that an analyst must review; it drives no action beyond the alert-threshold comparison.
- **pytm mitigations:** Implement layered defense with both system prompts and content filtering. Use output filtering to detect and block policy-violating responses. Regularly test with adversarial prompts and update defenses. Consider using classifier models to detect jailbreaking attempts.

#### F-45 — Server Side Include (SSI) Injection  `INP03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-53 — Format String Injection  `INP08`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-54 — LDAP Injection  `INP09`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-56 — Relative Path Traversal  `INP11`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-58 — Dictionary-based Password Attack  `CR03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-64 — Embedding Scripts within Scripts  `SC03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-65 — PHP Remote File Inclusion  `INP16`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-67 — XSS Using Alternate Syntax  `SC04`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-70 — Removing Important Client Functionality  `SC05`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-72 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-75 — Exploiting Trust in Client  `AA04`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-79 — XML Attribute Blowup  `INP22`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-80 — XSS Targeting URI Placeholders  `INP28`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-82 — SOAP Array Overflow  `INP34`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-84 — HTTP Request Smuggling  `INP37`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-85 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-94 — Format String Injection  `INP08`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-95 — Client-side Injection-induced Buffer Overflow  `INP12`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** The client software should not install untrusted code from a non-authenticated server. The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers. Perform input validation for length of buffer inputs. Use a language or compiler that performs automatic bounds checking. Use an abstraction library to abstract away risky APIs. Not a complete solution. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Ensure all buffer uses are consistently bounds-checked. Use OS-level preventative functionality. Not a complete solution.

#### F-96 — Command Delimiters  `INP13`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Perform whitelist validation against a positive specification for command length, type, and parameters.Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running under a privileged accountImplementation: Perform input validation for all remote content.Implementation: Use type conversions such as JDBC prepared statements.

#### F-99 — iFrame Overlay  `INP20`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Configuration: Disable iFrames in the Web browser.Operation: When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.Operation: If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.

#### F-101 — Privilege Escalation  `AC12`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-104 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-105 — Resource Injection  `INP25`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Ensure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-106 — Code Injection  `INP26`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Utilize strict type, character, and encoding enforcementEnsure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-108 — XSS Targeting URI Placeholders  `INP28`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-111 — Command Injection  `INP31`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary.Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter.Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.

#### F-112 — XML Injection  `INP32`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.

#### F-113 — Remote Code Inclusion  `INP33`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize attacks by input validation and sanitization of any user data that will be used by the target application to locate a remote file to be included.

#### F-114 — Leverage Alternate Encoding  `INP35`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input.

#### F-115 — Schema Poisoning  `AC15`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Schema handling inside oauth2-proxy and connector-misp is upstream's; the orchestrator validates everything it receives from either side.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-117 — Argument Injection  `INP41`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out all unauthorized commands and characters in the process.Design: Limit program privileges, so if metacharacters or other methods circumvent program input validation routines and shell access is attained then it is not running under a privileged account. chroot jails create a sandbox for the application to execute in, making it more difficult for an attacker to elevate privilege even in the case that a compromise has occurred.Implementation: Implement an audit log that is written to a separate host, in the event of a compromise the audit log may be able to provide evidence and details of the compromise.

#### F-118 — Reusing Session IDs (aka Session Replay) - ClientSide  `AC20`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-119 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-120 — Session Sidejacking  `CR01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-129 — Format String Injection  `INP08`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-130 — LDAP Injection  `INP09`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-132 — Relative Path Traversal  `INP11`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-139 — Embedding Scripts within Scripts  `SC03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-140 — PHP Remote File Inclusion  `INP16`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-144 — XSS Using Alternate Syntax  `SC04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-147 — Removing Important Client Functionality  `SC05`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-149 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Keycloak (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-152 — Exploiting Trust in Client  `AA04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-156 — XML Attribute Blowup  `INP22`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-157 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-159 — SOAP Array Overflow  `INP34`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-161 — HTTP Request Smuggling  `INP37`

- **Element:** Keycloak (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-162 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-164 — Reusing Session IDs (aka Session Replay) - ServerSide  `AC19`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-167 — Exploit Test APIs  `API01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — No test or debug endpoints ship; /docs is the read-only OpenAPI UI and every data route behind it still requires the API key (tests assert 401 without it).
- **pytm mitigations:** Ensure that production systems to not contain sample or test APIs and that these APIs are only used in development environments.

#### F-170 — Privilege Escalation  `AC12`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-173 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-174 — Schema Poisoning  `AC15`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-180 — Privilege Escalation  `AC12`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-182 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-183 — Schema Poisoning  `AC15`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-188 — Audit Log Manipulation  `DE04`

- **Element:** SQLite run store (store)
- **Response:** accepted — Run rows are outside the manifest chain: /targets/{id}/chain/verify checks the manifest hash, signature, chain link and artefact files (evidence.py), not a row's status, collectors or timestamps, so an edit to those fields with the manifest intact goes undetected. Hardening: database file permissions, backups and disk encryption.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-192 — Audit Log Manipulation  `DE04`

- **Element:** targets.yaml (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-196 — Audit Log Manipulation  `DE04`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-201 — Audit Log Manipulation  `DE04`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007): tampering with daily_reports is detectable through /targets/{id}/chain/verify. targets.yaml is mounted read-only. The Amass asset database carries collector input, not audit data. Application logs are stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-202 — Server Side Include (SSI) Injection  `INP03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-211 — Format String Injection  `INP08`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-212 — LDAP Injection  `INP09`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-214 — Relative Path Traversal  `INP11`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-216 — Dictionary-based Password Attack  `CR03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-222 — Embedding Scripts within Scripts  `SC03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-223 — PHP Remote File Inclusion  `INP16`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-226 — XSS Using Alternate Syntax  `SC04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-229 — Removing Important Client Functionality  `SC05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-231 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-234 — Exploiting Trust in Client  `AA04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-238 — XML Attribute Blowup  `INP22`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-239 — XSS Targeting URI Placeholders  `INP28`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-241 — SOAP Array Overflow  `INP34`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-243 — HTTP Request Smuggling  `INP37`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-244 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-246 — Server Side Include (SSI) Injection  `INP03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-255 — Format String Injection  `INP08`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-256 — LDAP Injection  `INP09`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-258 — Relative Path Traversal  `INP11`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-260 — Dictionary-based Password Attack  `CR03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-266 — Embedding Scripts within Scripts  `SC03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-267 — PHP Remote File Inclusion  `INP16`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-270 — XSS Using Alternate Syntax  `SC04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-273 — Removing Important Client Functionality  `SC05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-275 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-278 — Exploiting Trust in Client  `AA04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-282 — XML Attribute Blowup  `INP22`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-283 — XSS Targeting URI Placeholders  `INP28`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-285 — SOAP Array Overflow  `INP34`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-287 — HTTP Request Smuggling  `INP37`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-288 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-290 — Server Side Include (SSI) Injection  `INP03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-299 — Format String Injection  `INP08`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-300 — LDAP Injection  `INP09`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-302 — Relative Path Traversal  `INP11`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-304 — Dictionary-based Password Attack  `CR03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-310 — Embedding Scripts within Scripts  `SC03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator renders nothing from the sidecars; its own console is CSP-locked (default-src 'none', no inline script). SpiderFoot's web UI is loopback-only.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-311 — PHP Remote File Inclusion  `INP16`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-314 — XSS Using Alternate Syntax  `SC04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-317 — Removing Important Client Functionality  `SC05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No security decision of the orchestrator lives in a sidecar's client code; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-319 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-322 — Exploiting Trust in Client  `AA04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-326 — XML Attribute Blowup  `INP22`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-327 — XSS Targeting URI Placeholders  `INP28`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-329 — SOAP Array Overflow  `INP34`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-331 — HTTP Request Smuggling  `INP37`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-332 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-334 — Direct Prompt Injection  `LLM01`

- **Element:** Ollama (local models) (sidecar)
- **Response:** accepted — Collected text reaches the model delimited and flattened, replies are JSON-schema validated, and the model has no tools, so an injected instruction cannot execute anything. It can still skew the assessment: a schema-valid risk level feeds alert_case_reason (pipeline.py, alerts/__init__.py) and can raise or suppress a risk-threshold alert. Residual risk accepted: the new-observables rule fires independently of the model, the evidence and rationale stay visible to the analyst, and model output is an aid, not a determination (README, Responsible use).
- **pytm mitigations:** Implement input content filtering and guardrails. Use prompt engineering techniques to make the system prompt more robust against injection. Apply output validation to detect and block manipulated responses. Monitor and log prompts for anomalous patterns.

#### F-335 — Jailbreaking and Safety Bypass  `LLM07`

- **Element:** Ollama (local models) (sidecar)
- **Response:** accepted — Same as LLM01: a jailbroken reply is either rejected by the schema or lands as a plausible-looking but wrong assessment that an analyst must review; it drives no action beyond the alert-threshold comparison.
- **pytm mitigations:** Implement layered defense with both system prompts and content filtering. Use output filtering to detect and block policy-violating responses. Regularly test with adversarial prompts and update defenses. Consider using classifier models to detect jailbreaking attempts.

#### F-336 — Server Side Include (SSI) Injection  `INP03`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-344 — Format String Injection  `INP08`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-345 — LDAP Injection  `INP09`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-347 — Relative Path Traversal  `INP11`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-349 — Dictionary-based Password Attack  `CR03`

- **Element:** MISP (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-355 — Embedding Scripts within Scripts  `SC03`

- **Element:** MISP (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-356 — PHP Remote File Inclusion  `INP16`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-358 — XSS Using Alternate Syntax  `SC04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-361 — Removing Important Client Functionality  `SC05`

- **Element:** MISP (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-363 — Exploitation of Trusted Credentials  `AA03`

- **Element:** MISP (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-366 — Exploiting Trust in Client  `AA04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-370 — XML Attribute Blowup  `INP22`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-371 — XSS Targeting URI Placeholders  `INP28`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-373 — SOAP Array Overflow  `INP34`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-375 — HTTP Request Smuggling  `INP37`

- **Element:** MISP (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-376 — Session Credential Falsification through Prediction  `AC16`

- **Element:** MISP (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-378 — Server Side Include (SSI) Injection  `INP03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

#### F-379 — Session Sidejacking  `CR01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-388 — Format String Injection  `INP08`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-389 — LDAP Injection  `INP09`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.

#### F-391 — Relative Path Traversal  `INP11`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

#### F-397 — Embedding Scripts within Scripts  `SC03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The web surfaces of Keycloak, MISP, Tavily and the SMTP relay are the vendor's.
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-398 — PHP Remote File Inclusion  `INP16`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives

#### F-402 — XSS Using Alternate Syntax  `SC04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-404 — Removing Important Client Functionality  `SC05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Client-side functionality of vendor UIs is the vendor's.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-406 — Exploitation of Trusted Credentials  `AA03`

- **Element:** OpenCTI platform (vendor)
- **Response:** accepted — Static long-lived tokens are the integration contract with OpenCTI (OPENCTI_ADMIN_TOKEN), MISP (MISP_KEY), Tavily, the SMTP relay and the cloud LLM; they live only in .env and environment variables and rotate manually. Hardening: a dedicated least-privilege token per connector and periodic rotation.
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-409 — Exploiting Trust in Client  `AA04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

#### F-413 — XML Attribute Blowup  `INP22`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-414 — XSS Targeting URI Placeholders  `INP28`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-416 — SOAP Array Overflow  `INP34`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-418 — HTTP Request Smuggling  `INP37`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-419 — Session Credential Falsification through Prediction  `AC16`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session identifiers of Keycloak, OpenCTI, MISP and Tavily are generated by the vendor; the orchestrator's own secrets are CSPRNG material (openssl rand guidance in .env.example).
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-421 — Reusing Session IDs (aka Session Replay) - ServerSide  `AC19`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-426 — Audit Log Manipulation  `DE04`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — OpenCTI's own audit trail lives in its backing stores and is the platform's.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-434 — Format String Injection  `INP08`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

#### F-435 — Client-side Injection-induced Buffer Overflow  `INP12`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** The client software should not install untrusted code from a non-authenticated server. The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers. Perform input validation for length of buffer inputs. Use a language or compiler that performs automatic bounds checking. Use an abstraction library to abstract away risky APIs. Not a complete solution. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Ensure all buffer uses are consistently bounds-checked. Use OS-level preventative functionality. Not a complete solution.

#### F-436 — Command Delimiters  `INP13`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Perform whitelist validation against a positive specification for command length, type, and parameters.Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running under a privileged accountImplementation: Perform input validation for all remote content.Implementation: Use type conversions such as JDBC prepared statements.

#### F-438 — Dictionary-based Password Attack  `CR03`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Password policy and lockout belong to Keycloak, MISP, Tavily and the SMTP relay.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-440 — iFrame Overlay  `INP20`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Configuration: Disable iFrames in the Web browser.Operation: When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.Operation: If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.

#### F-442 — Privilege Escalation  `AC12`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-445 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-446 — Resource Injection  `INP25`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Ensure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-447 — Code Injection  `INP26`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Utilize strict type, character, and encoding enforcementEnsure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.

#### F-449 — XSS Targeting URI Placeholders  `INP28`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

#### F-452 — Command Injection  `INP31`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary.Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter.Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.

#### F-453 — XML Injection  `INP32`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.

#### F-454 — Remote Code Inclusion  `INP33`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize attacks by input validation and sanitization of any user data that will be used by the target application to locate a remote file to be included.

#### F-455 — Leverage Alternate Encoding  `INP35`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input.

#### F-456 — Schema Poisoning  `AC15`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Schema handling inside oauth2-proxy and connector-misp is upstream's; the orchestrator validates everything it receives from either side.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-458 — Argument Injection  `INP41`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out all unauthorized commands and characters in the process.Design: Limit program privileges, so if metacharacters or other methods circumvent program input validation routines and shell access is attained then it is not running under a privileged account. chroot jails create a sandbox for the application to execute in, making it more difficult for an attacker to elevate privilege even in the case that a compromise has occurred.Implementation: Implement an audit log that is written to a separate host, in the event of a compromise the audit log may be able to provide evidence and details of the compromise.

#### F-459 — Reusing Session IDs (aka Session Replay) - ClientSide  `AC20`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-461 — Session Sidejacking  `CR01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback with AUTH_PROXY_COOKIE_SECURE=false: the session cookie is exposed to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front of the proxy and AUTH_PROXY_COOKIE_SECURE=true.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-466 — Communication Channel Manipulation  `CR06`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-469 — Unprotected Sensitive Data  `DR01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-470 — Credentials Disclosure  `AC23`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-471 — Session Sidejacking  `CR01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — The shipped OIDC overlay runs oauth2-proxy on plain HTTP on loopback with AUTH_PROXY_COOKIE_SECURE=false: the session cookie is exposed to anything on the host, which ADR-005 trusts. Production: a TLS terminator in front of the proxy and AUTH_PROXY_COOKIE_SECURE=true.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-476 — Communication Channel Manipulation  `CR06`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-479 — Unprotected Sensitive Data  `DR01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-480 — Credentials Disclosure  `AC23`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-484 — Communication Channel Manipulation  `CR06`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-487 — Unprotected Sensitive Data  `DR01`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-488 — Credentials Disclosure  `AC23`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-492 — Communication Channel Manipulation  `CR06`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-495 — Unprotected Sensitive Data  `DR01`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-496 — Credentials Disclosure  `AC23`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-500 — Communication Channel Manipulation  `CR06`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-503 — Unprotected Sensitive Data  `DR01`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-504 — Credentials Disclosure  `AC23`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-508 — Communication Channel Manipulation  `CR06`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-513 — Communication Channel Manipulation  `CR06`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-516 — Unprotected Sensitive Data  `DR01`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-517 — Credentials Disclosure  `AC23`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-521 — Communication Channel Manipulation  `CR06`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-526 — Communication Channel Manipulation  `CR06`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-529 — Unprotected Sensitive Data  `DR01`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-533 — Communication Channel Manipulation  `CR06`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-538 — Communication Channel Manipulation  `CR06`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-541 — Unprotected Sensitive Data  `DR01`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-545 — Communication Channel Manipulation  `CR06`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-548 — Unprotected Sensitive Data  `DR01`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-552 — Communication Channel Manipulation  `CR06`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-555 — Unprotected Sensitive Data  `DR01`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-559 — Communication Channel Manipulation  `CR06`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-561 — Credentials Disclosure  `AC23`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-565 — Communication Channel Manipulation  `CR06`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-567 — Credentials Disclosure  `AC23`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-571 — Communication Channel Manipulation  `CR06`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-573 — Credentials Disclosure  `AC23`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-577 — Communication Channel Manipulation  `CR06`

- **Element:** Active reconnaissance (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-582 — Communication Channel Manipulation  `CR06`

- **Element:** Passive collection (OpenOSINT) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-587 — Communication Channel Manipulation  `CR06`

- **Element:** Qualification & synthesis prompts (local) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-590 — Unprotected Sensitive Data  `DR01`

- **Element:** Qualification & synthesis prompts (local) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-594 — Communication Channel Manipulation  `CR06`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-596 — Credentials Disclosure  `AC23`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-600 — Communication Channel Manipulation  `CR06`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-603 — Unprotected Sensitive Data  `DR01`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-607 — Communication Channel Manipulation  `CR06`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-610 — Unprotected Sensitive Data  `DR01`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-614 — Communication Channel Manipulation  `CR06`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-619 — Communication Channel Manipulation  `CR06`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-622 — Unprotected Sensitive Data  `DR01`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-623 — Credentials Disclosure  `AC23`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-627 — Communication Channel Manipulation  `CR06`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-630 — Unprotected Sensitive Data  `DR01`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-634 — Communication Channel Manipulation  `CR06`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-637 — Unprotected Sensitive Data  `DR01`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-638 — Credentials Disclosure  `AC23`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-642 — Communication Channel Manipulation  `CR06`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-645 — Unprotected Sensitive Data  `DR01`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-646 — Credentials Disclosure  `AC23`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-650 — Communication Channel Manipulation  `CR06`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-653 — Unprotected Sensitive Data  `DR01`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-657 — Communication Channel Manipulation  `CR06`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-659 — Credentials Disclosure  `AC23`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-663 — Communication Channel Manipulation  `CR06`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-666 — Unprotected Sensitive Data  `DR01`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Data at rest is plaintext by decision ADR-005 (SQLite, daily_reports, the Amass asset database, OpenCTI stores) and host-internal hops carry it in clear (DS06). Hardening: encrypted volumes or disk encryption, TLS between services.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-667 — Credentials Disclosure  `AC23`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-671 — Communication Channel Manipulation  `CR06`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-676 — Communication Channel Manipulation  `CR06`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Internet hops are TLS 1.2+ and the supply channel is pinned (git dependencies by 40-character SHA, images by explicit tag). Host-internal hops are plaintext by decision (DS06) and can be manipulated only from the host itself. Hardening as in DS06.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-678 — Credentials Disclosure  `AC23`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Credentials cross the network only inside TLS (TAVILY_API_KEY, the LLM provider key, MISP_KEY, SMTP credentials) or on host-local plaintext hops: X-API-Key on the loopback API and through the proxied console, OPENCTI_ADMIN_TOKEN on the compose bridge from the sink and from connector-misp. They are never logged (parameterized logging, explicit extra fields). Hardening: TLS terminator in front of :8000/:8002 and TLS to OpenCTI.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

### Severity: Medium (307)

#### F-3 — Excavation  `DS01`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-4 — Double Encoding  `DE02`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-5 — Privilege Abuse  `AC01`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-6 — Flooding  `DO01`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-8 — Excessive Allocation  `DO02`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-11 — Parameter Injection  `INP10`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-13 — Input Data Manipulation  `INP14`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-19 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-22 — XSS Targeting Error Pages  `DS04`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-25 — Manipulate Registry Information  `AC08`

- **Element:** Tavily search API (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-27 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-29 — Functionality Misuse  `AC09`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-32 — XML External Entities Blowup  `INP19`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-33 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-34 — DTD Injection  `INP21`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-37 — XSS Using Doubled Characters  `INP29`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-39 — HTTP Response Smuggling  `INP36`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-47 — Excavation  `DS01`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-48 — Double Encoding  `DE02`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-49 — Privilege Abuse  `AC01`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-50 — Flooding  `DO01`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-52 — Excessive Allocation  `DO02`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-55 — Parameter Injection  `INP10`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-57 — Input Data Manipulation  `INP14`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-63 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-66 — XSS Targeting Error Pages  `DS04`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-69 — Manipulate Registry Information  `AC08`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-71 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-73 — Functionality Misuse  `AC09`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-76 — XML External Entities Blowup  `INP19`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-77 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-78 — DTD Injection  `INP21`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-81 — XSS Using Doubled Characters  `INP29`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-83 — HTTP Response Smuggling  `INP36`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-88 — Authentication Abuse/ByPass  `AA01`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-89 — Double Encoding  `DE02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-90 — Privilege Abuse  `AC01`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-92 — Flooding  `DO01`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-93 — Excessive Allocation  `DO02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-97 — Input Data Manipulation  `INP14`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-98 — Principal Spoof  `AA02`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-102 — Hijacking a privileged process  `AC13`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-107 — XSS Targeting HTML Attributes  `INP27`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list all input including that which is not expected to have any scripting content.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-109 — XSS Using Doubled Characters  `INP29`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-110 — XSS Using Invalid Characters  `INP30`

- **Element:** oauth2-proxy (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be included in any subsequent web pages or back end operations.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-122 — Authentication Abuse/ByPass  `AA01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-123 — Excavation  `DS01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-124 — Double Encoding  `DE02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-125 — Privilege Abuse  `AC01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-126 — Flooding  `DO01`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-128 — Excessive Allocation  `DO02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-131 — Parameter Injection  `INP10`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-133 — Input Data Manipulation  `INP14`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-138 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-141 — Principal Spoof  `AA02`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-142 — Session Credential Falsification through Forging  `CR04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-143 — XSS Targeting Error Pages  `DS04`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-146 — Manipulate Registry Information  `AC08`

- **Element:** Keycloak (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-148 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Keycloak (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-150 — Functionality Misuse  `AC09`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-153 — XML External Entities Blowup  `INP19`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-154 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-155 — DTD Injection  `INP21`

- **Element:** Keycloak (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-158 — XSS Using Doubled Characters  `INP29`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-160 — HTTP Response Smuggling  `INP36`

- **Element:** Keycloak (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-166 — Authentication Abuse/ByPass  `AA01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests) under the assumption that ORCHESTRATOR_API_KEY is set; /health and /metrics are intentionally open; the console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-168 — Flooding  `DO01`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** accepted — No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-169 — Principal Spoof  `AA02`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds an authenticated person (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-171 — Hijacking a privileged process  `AC13`

- **Element:** Orchestrator API (FastAPI + APScheduler) (orchestrator)
- **Response:** mitigated — The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-177 — Authentication Abuse/ByPass  `AA01`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests) under the assumption that ORCHESTRATOR_API_KEY is set; /health and /metrics are intentionally open; the console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-178 — Flooding  `DO01`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** accepted — No rate limiting in the service; concurrency is bounded (409 on an active run, retry budgets, per-run call caps) and the API is loopback-only by default. Hardening: rate limiting at the proxy or TLS terminator.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-179 — Principal Spoof  `AA02`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds an authenticated person (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-181 — Hijacking a privileged process  `AC13`

- **Element:** APScheduler cron jobs (orchestrator)
- **Response:** mitigated — The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-185 — Privilege Abuse  `AC01`

- **Element:** SQLite run store (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-186 — Excessive Allocation  `DO02`

- **Element:** SQLite run store (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-189 — Privilege Abuse  `AC01`

- **Element:** targets.yaml (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-190 — Excessive Allocation  `DO02`

- **Element:** targets.yaml (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-193 — Privilege Abuse  `AC01`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-194 — Excessive Allocation  `DO02`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-197 — Privilege Abuse  `AC01`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — One process owns each volume (uid 1000 for the orchestrator's stores, the engine for asset.db); there is no finer privilege to abuse. Hardening: volume permissions and read-only mounts where possible.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-198 — Shared Data Manipulation  `AC02`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — The Amass asset database is shared between the engine and the orchestrator on one volume of the trusted host (ADR-005); oam_subs output is parsed as untrusted text.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. Use HTTPS/SSL for communication.

#### F-199 — Excessive Allocation  `DO02`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — Stores grow with runs: the scheduler's retention purge bounds SQLite rows and daily_reports; asset.db and targets.yaml grow with the inventory only. Hardening: disk quotas and monitoring on the volumes.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-204 — Authentication Abuse/ByPass  `AA01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-205 — Excavation  `DS01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-206 — Double Encoding  `DE02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-207 — Privilege Abuse  `AC01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-208 — Flooding  `DO01`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-210 — Excessive Allocation  `DO02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-213 — Parameter Injection  `INP10`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-215 — Input Data Manipulation  `INP14`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-221 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-224 — Principal Spoof  `AA02`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-225 — XSS Targeting Error Pages  `DS04`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-228 — Manipulate Registry Information  `AC08`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-230 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-232 — Functionality Misuse  `AC09`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-235 — XML External Entities Blowup  `INP19`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-236 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-237 — DTD Injection  `INP21`

- **Element:** SpiderFoot (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-240 — XSS Using Doubled Characters  `INP29`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-242 — HTTP Response Smuggling  `INP36`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-248 — Authentication Abuse/ByPass  `AA01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-249 — Excavation  `DS01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-250 — Double Encoding  `DE02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-251 — Privilege Abuse  `AC01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-252 — Flooding  `DO01`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-254 — Excessive Allocation  `DO02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-257 — Parameter Injection  `INP10`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-259 — Input Data Manipulation  `INP14`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-265 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-268 — Principal Spoof  `AA02`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-269 — XSS Targeting Error Pages  `DS04`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-272 — Manipulate Registry Information  `AC08`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-274 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-276 — Functionality Misuse  `AC09`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-279 — XML External Entities Blowup  `INP19`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-280 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-281 — DTD Injection  `INP21`

- **Element:** Amass v5 engine (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-284 — XSS Using Doubled Characters  `INP29`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-286 — HTTP Response Smuggling  `INP36`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-292 — Authentication Abuse/ByPass  `AA01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-293 — Excavation  `DS01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-294 — Double Encoding  `DE02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-295 — Privilege Abuse  `AC01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No roles on the sidecars: every caller can do everything they do (AA01).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-296 — Flooding  `DO01`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The sidecars can be flooded by anything on the compose network; the orchestrator bounds its own use with timeouts and per-run caps.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-298 — Excessive Allocation  `DO02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-301 — Parameter Injection  `INP10`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-303 — Input Data Manipulation  `INP14`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-309 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — There is no access control to misconfigure on the sidecars (AA01).
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-312 — Principal Spoof  `AA02`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The sidecars accept anything on the compose network as the orchestrator (AA01).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-313 — XSS Targeting Error Pages  `DS04`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-316 — Manipulate Registry Information  `AC08`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-318 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — The orchestrator's console sets X-Content-Type-Options: nosniff and a strict CSP; SpiderFoot's UI is loopback-only.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-320 — Functionality Misuse  `AC09`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Anything on the compose network can drive an unauthenticated sidecar (AA01); the orchestrator's own triggers are guarded by the in-progress 409 rule and per-target schedules.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-323 — XML External Entities Blowup  `INP19`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-324 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot, Amass, SocialOSINT and Ollama have no sessions and no authentication; they are reachable only on loopback or the compose bridge (ADR-005). Hardening for shared hosts: authentication in front of SpiderFoot and network policies between services.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-325 — DTD Injection  `INP21`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-328 — XSS Using Doubled Characters  `INP29`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-330 — HTTP Response Smuggling  `INP36`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — No proxy is chained in front of the sidecars: the orchestrator reaches them directly on the compose bridge, so smuggling needs a position on the host (ADR-005).
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-338 — Excavation  `DS01`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-339 — Double Encoding  `DE02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-340 — Privilege Abuse  `AC01`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-341 — Flooding  `DO01`

- **Element:** MISP (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-343 — Excessive Allocation  `DO02`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-346 — Parameter Injection  `INP10`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-348 — Input Data Manipulation  `INP14`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-354 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-357 — XSS Targeting Error Pages  `DS04`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-360 — Manipulate Registry Information  `AC08`

- **Element:** MISP (vendor)
- **Response:** accepted — Service discovery is static compose DNS on the trusted network; there is no registry to manipulate from outside the host.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-362 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** MISP (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-364 — Functionality Misuse  `AC09`

- **Element:** MISP (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-367 — XML External Entities Blowup  `INP19`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-368 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** MISP (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-369 — DTD Injection  `INP21`

- **Element:** MISP (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-372 — XSS Using Doubled Characters  `INP29`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-374 — HTTP Response Smuggling  `INP36`

- **Element:** MISP (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-381 — Authentication Abuse/ByPass  `AA01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-382 — Excavation  `DS01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.

#### F-383 — Double Encoding  `DE02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-384 — Privilege Abuse  `AC01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-385 — Flooding  `DO01`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-387 — Excessive Allocation  `DO02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-390 — Parameter Injection  `INP10`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.

#### F-392 — Input Data Manipulation  `INP14`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-399 — Principal Spoof  `AA02`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-400 — Session Credential Falsification through Forging  `CR04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-401 — XSS Targeting Error Pages  `DS04`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-405 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — MIME handling of vendor web UIs is the vendor's.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-407 — Functionality Misuse  `AC09`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-410 — XML External Entities Blowup  `INP19`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-411 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Session and credential handling inside Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator presents only API tokens.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-412 — DTD Injection  `INP21`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — The orchestrator's contracts are JSON and CLI text; it parses no XML, SOAP or DTD. Any XML handling lives inside the sidecar or vendor service and is upstream code.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-415 — XSS Using Doubled Characters  `INP29`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-417 — HTTP Response Smuggling  `INP36`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — HTTP parsing of Keycloak, OpenCTI, MISP, Tavily and the SMTP relay is the vendor's; the orchestrator sends well-formed requests from httpx, pycti and smtplib.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-422 — Privilege Abuse  `AC01`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-423 — Shared Data Manipulation  `AC02`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — OpenCTI's backing stores (Elasticsearch, MinIO, RabbitMQ, Redis) are owned and hardened by the OpenCTI platform deployment.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. Use HTTPS/SSL for communication.

#### F-424 — Excessive Allocation  `DO02`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-428 — Authentication Abuse/ByPass  `AA01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-429 — Double Encoding  `DE02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

#### F-430 — Privilege Abuse  `AC01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-432 — Flooding  `DO01`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Rate limiting of vendor services is the vendor's.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-433 — Excessive Allocation  `DO02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

#### F-437 — Input Data Manipulation  `INP14`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc.

#### F-439 — Principal Spoof  `AA02`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Authentication and authorisation inside Keycloak, OpenCTI, MISP, Tavily, oauth2-proxy and connector-misp are the vendor's.
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-443 — Hijacking a privileged process  `AC13`

- **Element:** connector-misp (vendor)
- **Response:** transferred — oauth2-proxy and connector-misp run as their pinned vendor images ship them; what happens inside them is upstream code.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-448 — XSS Targeting HTML Attributes  `INP27`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list all input including that which is not expected to have any scripting content.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-450 — XSS Using Doubled Characters  `INP29`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-451 — XSS Using Invalid Characters  `INP30`

- **Element:** connector-misp (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be included in any subsequent web pages or back end operations.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

#### F-463 — Interception  `DE01`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-464 — Content Spoofing  `AC05`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-465 — Sniffing Attacks  `DE03`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-467 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Operator session (OIDC, shipped overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-473 — Interception  `DE01`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-474 — Content Spoofing  `AC05`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-475 — Sniffing Attacks  `DE03`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-477 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Proxied console/API calls (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-481 — Interception  `DE01`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-482 — Content Spoofing  `AC05`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-483 — Sniffing Attacks  `DE03`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-485 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Token redeem / userinfo (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-489 — Interception  `DE01`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-490 — Content Spoofing  `AC05`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-491 — Sniffing Attacks  `DE03`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-493 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Operator login (Keycloak authorization endpoint, shipped overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-497 — Interception  `DE01`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-498 — Content Spoofing  `AC05`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-499 — Sniffing Attacks  `DE03`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-501 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Direct loopback API/console (no overlay) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-505 — Interception  `DE01`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-506 — Content Spoofing  `AC05`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-507 — Sniffing Attacks  `DE03`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-509 — Client-Server Protocol Manipulation  `CR08`

- **Element:** GET /health, /metrics (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-510 — Interception  `DE01`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-511 — Content Spoofing  `AC05`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-512 — Sniffing Attacks  `DE03`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-514 — Client-Server Protocol Manipulation  `CR08`

- **Element:** POST /bundles (STIX intake) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-518 — Interception  `DE01`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-519 — Content Spoofing  `AC05`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-520 — Sniffing Attacks  `DE03`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-522 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Cron dispatch (in-process) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-523 — Interception  `DE01`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-524 — Content Spoofing  `AC05`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-525 — Sniffing Attacks  `DE03`

- **Element:** Scan control & results (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-527 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Scan control & results (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-530 — Interception  `DE01`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-531 — Content Spoofing  `AC05`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-532 — Sniffing Attacks  `DE03`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-534 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Enumeration submit (oam_enum) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-535 — Interception  `DE01`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-536 — Content Spoofing  `AC05`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-537 — Sniffing Attacks  `DE03`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-539 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Engine writes asset.db (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-542 — Interception  `DE01`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-543 — Content Spoofing  `AC05`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-544 — Sniffing Attacks  `DE03`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-546 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read discovered names (oam_subs, shared volume) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-549 — Interception  `DE01`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-550 — Content Spoofing  `AC05`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-551 — Sniffing Attacks  `DE03`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-553 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Platform collection jobs (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-556 — Interception  `DE01`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-557 — Content Spoofing  `AC05`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-558 — Sniffing Attacks  `DE03`

- **Element:** SocialOSINT text and vision prompts (own endpoint and key) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-562 — Interception  `DE01`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-563 — Content Spoofing  `AC05`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-564 — Sniffing Attacks  `DE03`

- **Element:** Platform collection (operator's API tokens) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-568 — Interception  `DE01`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-569 — Content Spoofing  `AC05`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-570 — Sniffing Attacks  `DE03`

- **Element:** Due-diligence queries (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-574 — Interception  `DE01`

- **Element:** Active reconnaissance (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-575 — Content Spoofing  `AC05`

- **Element:** Active reconnaissance (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-576 — Sniffing Attacks  `DE03`

- **Element:** Active reconnaissance (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-579 — Interception  `DE01`

- **Element:** Passive collection (OpenOSINT) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-580 — Content Spoofing  `AC05`

- **Element:** Passive collection (OpenOSINT) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-581 — Sniffing Attacks  `DE03`

- **Element:** Passive collection (OpenOSINT) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-584 — Interception  `DE01`

- **Element:** Qualification & synthesis prompts (local) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-585 — Content Spoofing  `AC05`

- **Element:** Qualification & synthesis prompts (local) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-586 — Sniffing Attacks  `DE03`

- **Element:** Qualification & synthesis prompts (local) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-588 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Qualification & synthesis prompts (local) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-591 — Interception  `DE01`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-592 — Content Spoofing  `AC05`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-593 — Sniffing Attacks  `DE03`

- **Element:** Qualification & synthesis prompts (cloud) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-597 — Interception  `DE01`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-598 — Content Spoofing  `AC05`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-599 — Sniffing Attacks  `DE03`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-601 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Run/state SQL (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-604 — Interception  `DE01`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-605 — Content Spoofing  `AC05`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-606 — Sniffing Attacks  `DE03`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-608 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Seal run artefacts + manifest (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-611 — Interception  `DE01`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-612 — Content Spoofing  `AC05`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-613 — Sniffing Attacks  `DE03`

- **Element:** Read target inventory (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-615 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read target inventory (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-616 — Interception  `DE01`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-617 — Content Spoofing  `AC05`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-618 — Sniffing Attacks  `DE03`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-620 — Client-Server Protocol Manipulation  `CR08`

- **Element:** STIX ingest (pycti, outbox retries) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-624 — Interception  `DE01`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-625 — Content Spoofing  `AC05`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-626 — Sniffing Attacks  `DE03`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-628 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Elasticsearch indices (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-631 — Interception  `DE01`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-632 — Content Spoofing  `AC05`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-633 — Sniffing Attacks  `DE03`

- **Element:** MinIO objects (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-635 — Client-Server Protocol Manipulation  `CR08`

- **Element:** MinIO objects (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-639 — Interception  `DE01`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-640 — Content Spoofing  `AC05`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-641 — Sniffing Attacks  `DE03`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-643 — Client-Server Protocol Manipulation  `CR08`

- **Element:** RabbitMQ queues (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-647 — Interception  `DE01`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-648 — Content Spoofing  `AC05`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-649 — Sniffing Attacks  `DE03`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-651 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Redis cache (no authentication) (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-654 — Interception  `DE01`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-655 — Content Spoofing  `AC05`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-656 — Sniffing Attacks  `DE03`

- **Element:** connector-misp polls MISP events (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-660 — Interception  `DE01`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-661 — Content Spoofing  `AC05`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-662 — Sniffing Attacks  `DE03`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-664 — Client-Server Protocol Manipulation  `CR08`

- **Element:** connector-misp writes to OpenCTI (flow)
- **Response:** accepted — The orchestrator validates protocol and headers on everything it serves and sends well-formed requests; POST /bundles parses its body as JSON without checking the declared media type, and the schema validation that follows is what bounds it. Manipulating a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Use strong authentication protocols.

#### F-668 — Interception  `DE01`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-669 — Content Spoofing  `AC05`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-670 — Sniffing Attacks  `DE03`

- **Element:** Alert webhook (ALERT_WEBHOOK_URL) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-673 — Interception  `DE01`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process, files) are within the trusted boundary of ADR-005; everything that leaves the host is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-674 — Content Spoofing  `AC05`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Everything that arrives through these flows is treated as untrusted text: escaped by React under CSP in the console, delimited in prompts, validated as STIX on intake. Spoofing the content of a host-internal plaintext hop needs a position on the host (DS06).
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-675 — Sniffing Attacks  `DE03`

- **Element:** Alert e-mail (SMTP, STARTTLS by default) (flow)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modelled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

### Severity: Low (29)

#### F-17 — Web Application Fingerprinting  `HA03`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-24 — Encryption Brute Forcing  `CR05`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-30 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-61 — Web Application Fingerprinting  `HA03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-68 — Encryption Brute Forcing  `CR05`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-74 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-136 — Web Application Fingerprinting  `HA03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-145 — Encryption Brute Forcing  `CR05`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-151 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-187 — Encryption Brute Forcing  `CR05`

- **Element:** SQLite run store (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-191 — Encryption Brute Forcing  `CR05`

- **Element:** targets.yaml (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-195 — Encryption Brute Forcing  `CR05`

- **Element:** daily_reports (sealed runs) (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-200 — Encryption Brute Forcing  `CR05`

- **Element:** Amass asset database (shared volume) (store)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01).
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-219 — Web Application Fingerprinting  `HA03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-227 — Encryption Brute Forcing  `CR05`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-233 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-263 — Web Application Fingerprinting  `HA03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-271 — Encryption Brute Forcing  `CR05`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-277 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-307 — Web Application Fingerprinting  `HA03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-315 — Encryption Brute Forcing  `CR05`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Nothing is encrypted at rest to brute-force (DR01); the orchestrator's keys and HMACs are 128-256-bit CSPRNG material.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-321 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Input handling inside the sidecar is upstream code the orchestrator does not change; the sidecar is reachable only on loopback or the compose bridge (ADR-005) and its output is parsed as untrusted text into CollectorResult. Hardening: network policies, read-only root filesystems, keeping the pinned images current.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-352 — Web Application Fingerprinting  `HA03`

- **Element:** MISP (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-359 — Encryption Brute Forcing  `CR05`

- **Element:** MISP (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-365 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** MISP (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-395 — Web Application Fingerprinting  `HA03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Fingerprinting a vendor service is the vendor's concern; Keycloak, OpenCTI and MISP are loopback-only here, Tavily and the SMTP relay are public services.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-403 — Encryption Brute Forcing  `CR05`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-408 — Fuzzing and observing application log data/errors for application mapping  `INP18`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Input handling inside the vendor service is the vendor's; the orchestrator sends it well-formed requests built from validated data and renders nothing it serves.
- **pytm mitigations:** Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.

#### F-425 — Encryption Brute Forcing  `CR05`

- **Element:** OpenCTI backing stores (vendor)
- **Response:** transferred — Cryptography inside vendor services is the vendor's.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

### Severity: Very Low (8)

#### F-15 — Footprinting  `DS03`

- **Element:** Tavily search API (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-59 — Footprinting  `DS03`

- **Element:** SMTP relay (alert e-mail) (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-134 — Footprinting  `DS03`

- **Element:** Keycloak (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-217 — Footprinting  `DS03`

- **Element:** SpiderFoot (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-261 — Footprinting  `DS03`

- **Element:** Amass v5 engine (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-305 — Footprinting  `DS03`

- **Element:** SocialOSINT sidecar (sidecar)
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-350 — Footprinting  `DS03`

- **Element:** MISP (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

#### F-393 — Footprinting  `DS03`

- **Element:** OpenCTI platform (vendor)
- **Response:** transferred — Footprinting a vendor service is the vendor's concern; the loopback-only ones expose no external surface from this deployment.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.
