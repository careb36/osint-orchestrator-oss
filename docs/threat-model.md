# Threat model — OSINT Orchestrator (OWASP pytm, threat library 114 threats)

Modular monolith (ADR-001): one FastAPI process with an in-process APScheduler and a SQLite store drives OSINT collectors, qualifies evidence with an LLM, normalises findings to STIX 2.1 (ADR-002), ingests them into OpenCTI (ADR-003/008), seals a signed report chain per run (ADR-007) and dispatches alerts. Access uses static API keys and a single instance (ADR-005), with an optional OIDC proxy perimeter (ADR-006) and an external STIX intake (ADR-011). Operator prose is Spanish, code English (ADR-004).

## Assumptions

- Single-instance deployment on a trusted Docker host; loopback-published ports are reachable only from that host.
- The Docker host and the compose network are operated by the same team as the orchestrator.
- Collectors only query targets authorised in targets.yaml (operator attestation per target).
- OpenCTI, MISP and the OIDC overlay are optional deployments; the model covers them when enabled.

## Findings: 343 across 48 distinct threats

Every finding carries a triage response:

- **accepted**: 96 finding(s)
- **mitigated**: 188 finding(s)
- **transferred**: 59 finding(s)

## Triage summary by threat

| Threat | Severity | Response | Rationale |
| --- | --- | --- | --- |
| AA01 Authentication Abuse/ByPass | Medium | mitigated | Every data route depends on require_api_key (401 asserted by tests); /health and /metrics are intentionally open and documented; the public console shell carries no data (ADR-010). |
| AA02 Principal Spoof | Medium | mitigated | Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds real authenticated identity where needed (ADR-006). |
| AA03 Exploitation of Trusted Credentials | High | accepted | Static API keys are the documented decision ADR-005; rotation is supported (comma-separated key set, ORCHESTRATOR_SECRET_KEY_PREVIOUS). Installations needing per-user identity deploy the OIDC overlay (ADR-006). |
| AC01 Privilege Abuse | Medium | accepted | One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization. |
| AC02 Shared Data Manipulation | Medium | transferred | OpenCTI backing stores (Elastic/MinIO/Rabbit/Redis) are owned and hardened by the OpenCTI platform deployment. |
| AC05 Content Spoofing | Medium | mitigated | Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served. |
| AC06 Using Malicious Files | Very High | mitigated | Collectors return structured CollectorResult; raw tool output never leaves the collector module (docs/architecture.md). Artefacts are never executed; the console renders escaped text under CSP default-src 'none'. |
| AC07 Exploiting Incorrectly Configured Access Control Security Levels | Medium | mitigated | Access control is enforced by a router-level dependency plus route tests; the console shell serves only the bundle, never data. |
| AC08 Manipulate Registry Information | Medium | transferred | No dynamic service registry or DNS-SD: compose service names are static and internal to the trusted network. |
| AC09 Functionality Misuse | Medium | accepted | Run triggers are guarded by the in-progress 409 rule and per-target schedules; retention purge is operator-configured cron. |
| AC11 Session Credential Falsification through Manipulation | Medium | mitigated | Tokens/keys are opaque CSPRNG values; artefact integrity is verifiable through the signed manifest chain (ADR-007). |
| AC12 Privilege Escalation | High | mitigated | No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to. |
| AC13 Hijacking a privileged process | Medium | mitigated | The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack. |
| AC14 Catching exception throw/signal from privileged block | Very High | mitigated | The pipeline isolates every step (collect/qualify/normalise/synthesise/seal/alert): a raised error fails the run, never a privileged transaction; the process runs as uid 1000 with no setuid paths (Dockerfile). |
| AC15 Schema Poisoning | High | mitigated | STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage. |
| AC16 Session Credential Falsification through Prediction | High | mitigated | All secrets and session material are CSPRNG-generated (openssl/uuid guidance in .env.example, secrets.token_urlsafe nonces); run ids are sequential but are not credentials. |
| AC17 Session Hijacking - ServerSide | Very High | accepted | Sidecars and vendor servers sit on the trusted compose network or loopback only (ADR-005 single host). Hardening for shared hosts: network policies + TLS between services. |
| AC19 Reusing Session IDs (aka Session Replay) - ServerSide | High | transferred | Session management of Keycloak and OpenCTI is vendor-owned; both are published on loopback only in this deployment. |
| AC21 Cross Site Request Forgery | Very High | mitigated | Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no cookie to forge cross-site; the console CSP sets form-action 'none'; the OIDC overlay implements CSRF tokens (oauth2-proxy). |
| AC23 Credentials Disclosure | High | mitigated | Credentials travel only in env/.env (git-ignored), never in logs (parameterized logging, explicit extra fields), and provider keys are sent exclusively over TLS; the console CSP forbids inline script exfiltration. |
| API01 Exploit Test APIs | High | mitigated | No test or debug endpoints ship; /docs is the read-only OpenAPI UI and every data route behind it still requires the API key (tests assert 401 without it). |
| CR01 Session Sidejacking | High | accepted | Plaintext session flows are loopback/compose-internal on a trusted host; oauth2-proxy COOKIE_SECURE=false is a local-dev overlay setting — production deployments must set it true behind TLS. |
| CR03 Dictionary-based Password Attack | High | transferred | The orchestrator holds no passwords (key-only auth, ADR-005); password policies belong to Keycloak/MISP/OpenCTI vendor auth. |
| CR04 Session Credential Falsification through Forging | Medium | transferred | Session token signing/verification belongs to Keycloak and OpenCTI vendor implementations. |
| CR05 Encryption Brute Forcing | Low | mitigated | Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible. |
| CR06 Communication Channel Manipulation | High | mitigated | Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local. |
| CR08 Client-Server Protocol Manipulation | Medium | mitigated | Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model. |
| DE01 Interception | Medium | accepted | Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS. |
| DE03 Sniffing Attacks | Medium | accepted | Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope. |
| DE04 Audit Log Manipulation | High | mitigated | Run artefacts are HMAC-signed and chained per target (ADR-007), so tampering is detectable via /targets/{id}/chain/verify; application logs are append-only stdout for the operator's shipper. |
| DO01 Flooding | Medium | mitigated | Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production. |
| DR01 Unprotected Sensitive Data | High | accepted | SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption. |
| DS03 Footprinting | Very Low | accepted | Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments. |
| DS06 Data Leak | Very High | mitigated | Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables. |
| HA03 Web Application Fingerprinting | Low | accepted | SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself. |
| INP02 Overflow Buffers | Very High | mitigated | Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS, PAGE) and LLM_MAX_OBSERVABLES_IN_PROMPT. |
| INP17 XSS Using MIME Type Mismatch | Medium | mitigated | X-Content-Type-Options: nosniff on every console response and asset, plus CSP, remove MIME-confusion XSS. |
| INP19 XML External Entities Blowup | Medium | transferred | No XML parsing in the orchestrator (JSON-only contract); XXE surface, if any, is upstream. |
| INP21 DTD Injection | Medium | transferred | No DTD processing exists in the orchestrator stack. |
| INP22 XML Attribute Blowup | High | transferred | The orchestrator parses JSON only (no XML/SOAP/DTD anywhere in the API); XML handling, if any, lives in upstream vendor services. |
| INP24 Filter Failure through Buffer Overflow | High | mitigated | Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing. |
| INP34 SOAP Array Overflow | High | transferred | No SOAP stack in the orchestrator; applies only to upstream vendor services. |
| INP36 HTTP Response Smuggling | Medium | transferred | Same single-server argument as INP37; response smuggling needs a chained proxy this deployment does not have. |
| INP37 HTTP Request Smuggling | High | transferred | Single uvicorn/h11 server with no chained proxy in the default deployment; the optional overlay uses maintained oauth2-proxy. |
| LLM01 Direct Prompt Injection | High | mitigated | Collected text reaches models as delimited, flattened untrusted data; replies are schema-validated and invalid items dropped and counted; models have no tools/agents, so injection cannot execute (docs/architecture.md, LLM routing). |
| LLM07 Jailbreaking and Safety Bypass | High | accepted | Synthesis is advisory: risk levels are validated against the persisted enum and never drive control flow; a jailbroken reply degrades to a dropped/invalid item, not an action. |
| SC03 Embedding Scripts within Scripts | High | mitigated | Console CSP is default-src 'none'; script-src/style-src 'self' with hashed build bundles and no inline script (CI checks the built index.html). |
| SC05 Removing Important Client Functionality | High | mitigated | CSP base-uri 'none' and frame-ancestors 'none' plus nosniff prevent script-stripping attacks; no security decision lives client-side. |

## Full findings

### Severity: Very High (37)

#### F-4 — Using Malicious Files  `AC06`

- **Element:** Tavily search API
- **Response:** mitigated — Collectors return structured CollectorResult; raw tool output never leaves the collector module (docs/architecture.md). Artefacts are never executed; the console renders escaped text under CSP default-src 'none'.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-21 — Session Hijacking - ServerSide  `AC17`

- **Element:** Tavily search API
- **Response:** accepted — Sidecars and vendor servers sit on the trusted compose network or loopback only (ADR-005 single host). Hardening for shared hosts: network policies + TLS between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-24 — Overflow Buffers  `INP02`

- **Element:** oauth2-proxy
- **Response:** mitigated — Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS, PAGE) and LLM_MAX_OBSERVABLES_IN_PROMPT.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-37 — Using Malicious Files  `AC06`

- **Element:** Keycloak
- **Response:** mitigated — Collectors return structured CollectorResult; raw tool output never leaves the collector module (docs/architecture.md). Artefacts are never executed; the console renders escaped text under CSP default-src 'none'.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-56 — Session Hijacking - ServerSide  `AC17`

- **Element:** Keycloak
- **Response:** accepted — Sidecars and vendor servers sit on the trusted compose network or loopback only (ADR-005 single host). Hardening for shared hosts: network policies + TLS between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-58 — Overflow Buffers  `INP02`

- **Element:** Orchestrator API (FastAPI + APScheduler)
- **Response:** mitigated — Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS, PAGE) and LLM_MAX_OBSERVABLES_IN_PROMPT.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-65 — Catching exception throw/signal from privileged block  `AC14`

- **Element:** Orchestrator API (FastAPI + APScheduler)
- **Response:** mitigated — The pipeline isolates every step (collect/qualify/normalise/synthesise/seal/alert): a raised error fails the run, never a privileged transaction; the process runs as uid 1000 with no setuid paths (Dockerfile).
- **pytm mitigations:** Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.

#### F-68 — Cross Site Request Forgery  `AC21`

- **Element:** Orchestrator API (FastAPI + APScheduler)
- **Response:** mitigated — Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no cookie to forge cross-site; the console CSP sets form-action 'none'; the OIDC overlay implements CSRF tokens (oauth2-proxy).
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-69 — Overflow Buffers  `INP02`

- **Element:** APScheduler cron jobs
- **Response:** mitigated — Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS, PAGE) and LLM_MAX_OBSERVABLES_IN_PROMPT.
- **pytm mitigations:** Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

#### F-79 — Cross Site Request Forgery  `AC21`

- **Element:** APScheduler cron jobs
- **Response:** mitigated — Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no cookie to forge cross-site; the console CSP sets form-action 'none'; the OIDC overlay implements CSRF tokens (oauth2-proxy).
- **pytm mitigations:** Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

#### F-94 — Using Malicious Files  `AC06`

- **Element:** SpiderFoot
- **Response:** mitigated — Collectors return structured CollectorResult; raw tool output never leaves the collector module (docs/architecture.md). Artefacts are never executed; the console renders escaped text under CSP default-src 'none'.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-113 — Session Hijacking - ServerSide  `AC17`

- **Element:** SpiderFoot
- **Response:** accepted — Sidecars and vendor servers sit on the trusted compose network or loopback only (ADR-005 single host). Hardening for shared hosts: network policies + TLS between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-118 — Using Malicious Files  `AC06`

- **Element:** Amass v5 engine
- **Response:** mitigated — Collectors return structured CollectorResult; raw tool output never leaves the collector module (docs/architecture.md). Artefacts are never executed; the console renders escaped text under CSP default-src 'none'.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-136 — Session Hijacking - ServerSide  `AC17`

- **Element:** Amass v5 engine
- **Response:** accepted — Sidecars and vendor servers sit on the trusted compose network or loopback only (ADR-005 single host). Hardening for shared hosts: network policies + TLS between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-141 — Using Malicious Files  `AC06`

- **Element:** SocialOSINT sidecar
- **Response:** mitigated — Collectors return structured CollectorResult; raw tool output never leaves the collector module (docs/architecture.md). Artefacts are never executed; the console renders escaped text under CSP default-src 'none'.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-159 — Session Hijacking - ServerSide  `AC17`

- **Element:** SocialOSINT sidecar
- **Response:** accepted — Sidecars and vendor servers sit on the trusted compose network or loopback only (ADR-005 single host). Hardening for shared hosts: network policies + TLS between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-165 — Using Malicious Files  `AC06`

- **Element:** MISP
- **Response:** mitigated — Collectors return structured CollectorResult; raw tool output never leaves the collector module (docs/architecture.md). Artefacts are never executed; the console renders escaped text under CSP default-src 'none'.
- **pytm mitigations:** Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

#### F-182 — Session Hijacking - ServerSide  `AC17`

- **Element:** MISP
- **Response:** accepted — Sidecars and vendor servers sit on the trusted compose network or loopback only (ADR-005 single host). Hardening for shared hosts: network policies + TLS between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-202 — Session Hijacking - ServerSide  `AC17`

- **Element:** OpenCTI platform
- **Response:** accepted — Sidecars and vendor servers sit on the trusted compose network or loopback only (ADR-005 single host). Hardening for shared hosts: network policies + TLS between services.
- **pytm mitigations:** Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

#### F-213 — Data Leak  `DS06`

- **Element:** Operator session (OIDC)
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-220 — Data Leak  `DS06`

- **Element:** Proxied console/API calls
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-227 — Data Leak  `DS06`

- **Element:** Direct loopback API/console (no overlay)
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-240 — Data Leak  `DS06`

- **Element:** POST /bundles (STIX intake)
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-253 — Data Leak  `DS06`

- **Element:** Scan control & results
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-260 — Data Leak  `DS06`

- **Element:** Enumeration submit/read (oam_enum/oam_subs)
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-267 — Data Leak  `DS06`

- **Element:** Platform collection jobs
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-273 — Data Leak  `DS06`

- **Element:** Due-diligence queries
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-279 — Data Leak  `DS06`

- **Element:** Active reconnaissance
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-284 — Data Leak  `DS06`

- **Element:** Passive collection (OpenOSINT)
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-290 — Data Leak  `DS06`

- **Element:** Qualification & synthesis prompts (local)
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-296 — Data Leak  `DS06`

- **Element:** Qualification & synthesis prompts (cloud)
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-303 — Data Leak  `DS06`

- **Element:** Run/state SQL
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-310 — Data Leak  `DS06`

- **Element:** Seal run artefacts + manifest
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-322 — Data Leak  `DS06`

- **Element:** STIX ingest (pycti, outbox retries)
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-330 — Data Leak  `DS06`

- **Element:** Index/object/queue traffic
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-336 — Data Leak  `DS06`

- **Element:** connector-misp event sync
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-342 — Data Leak  `DS06`

- **Element:** Token redeem / userinfo
- **Response:** mitigated — Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

### Severity: High (116)

#### F-3 — Dictionary-based Password Attack  `CR03`

- **Element:** Tavily search API
- **Response:** transferred — The orchestrator holds no passwords (key-only auth, ADR-005); password policies belong to Keycloak/MISP/OpenCTI vendor auth.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-6 — Embedding Scripts within Scripts  `SC03`

- **Element:** Tavily search API
- **Response:** mitigated — Console CSP is default-src 'none'; script-src/style-src 'self' with hashed build bundles and no inline script (CI checks the built index.html).
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-9 — Removing Important Client Functionality  `SC05`

- **Element:** Tavily search API
- **Response:** mitigated — CSP base-uri 'none' and frame-ancestors 'none' plus nosniff prevent script-stripping attacks; no security decision lives client-side.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-11 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Tavily search API
- **Response:** accepted — Static API keys are the documented decision ADR-005; rotation is supported (comma-separated key set, ORCHESTRATOR_SECRET_KEY_PREVIOUS). Installations needing per-user identity deploy the OIDC overlay (ADR-006).
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-16 — XML Attribute Blowup  `INP22`

- **Element:** Tavily search API
- **Response:** transferred — The orchestrator parses JSON only (no XML/SOAP/DTD anywhere in the API); XML handling, if any, lives in upstream vendor services.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-17 — SOAP Array Overflow  `INP34`

- **Element:** Tavily search API
- **Response:** transferred — No SOAP stack in the orchestrator; applies only to upstream vendor services.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-19 — HTTP Request Smuggling  `INP37`

- **Element:** Tavily search API
- **Response:** transferred — Single uvicorn/h11 server with no chained proxy in the default deployment; the optional overlay uses maintained oauth2-proxy.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-20 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Tavily search API
- **Response:** mitigated — All secrets and session material are CSPRNG-generated (openssl/uuid guidance in .env.example, secrets.token_urlsafe nonces); run ids are sequential but are not credentials.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-22 — Direct Prompt Injection  `LLM01`

- **Element:** Cloud LLM provider
- **Response:** mitigated — Collected text reaches models as delimited, flattened untrusted data; replies are schema-validated and invalid items dropped and counted; models have no tools/agents, so injection cannot execute (docs/architecture.md, LLM routing).
- **pytm mitigations:** Implement input content filtering and guardrails. Use prompt engineering techniques to make the system prompt more robust against injection. Apply output validation to detect and block manipulated responses. Monitor and log prompts for anomalous patterns.

#### F-23 — Jailbreaking and Safety Bypass  `LLM07`

- **Element:** Cloud LLM provider
- **Response:** accepted — Synthesis is advisory: risk levels are validated against the persisted enum and never drive control flow; a jailbroken reply degrades to a dropped/invalid item, not an action.
- **pytm mitigations:** Implement layered defense with both system prompts and content filtering. Use output filtering to detect and block policy-violating responses. Regularly test with adversarial prompts and update defenses. Consider using classifier models to detect jailbreaking attempts.

#### F-29 — Privilege Escalation  `AC12`

- **Element:** oauth2-proxy
- **Response:** mitigated — No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-31 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** oauth2-proxy
- **Response:** mitigated — Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-32 — Schema Poisoning  `AC15`

- **Element:** oauth2-proxy
- **Response:** mitigated — STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-33 — Session Sidejacking  `CR01`

- **Element:** Keycloak
- **Response:** accepted — Plaintext session flows are loopback/compose-internal on a trusted host; oauth2-proxy COOKIE_SECURE=false is a local-dev overlay setting — production deployments must set it true behind TLS.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-39 — Embedding Scripts within Scripts  `SC03`

- **Element:** Keycloak
- **Response:** mitigated — Console CSP is default-src 'none'; script-src/style-src 'self' with hashed build bundles and no inline script (CI checks the built index.html).
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-44 — Removing Important Client Functionality  `SC05`

- **Element:** Keycloak
- **Response:** mitigated — CSP base-uri 'none' and frame-ancestors 'none' plus nosniff prevent script-stripping attacks; no security decision lives client-side.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-46 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Keycloak
- **Response:** accepted — Static API keys are the documented decision ADR-005; rotation is supported (comma-separated key set, ORCHESTRATOR_SECRET_KEY_PREVIOUS). Installations needing per-user identity deploy the OIDC overlay (ADR-006).
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-51 — XML Attribute Blowup  `INP22`

- **Element:** Keycloak
- **Response:** transferred — The orchestrator parses JSON only (no XML/SOAP/DTD anywhere in the API); XML handling, if any, lives in upstream vendor services.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-52 — SOAP Array Overflow  `INP34`

- **Element:** Keycloak
- **Response:** transferred — No SOAP stack in the orchestrator; applies only to upstream vendor services.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-54 — HTTP Request Smuggling  `INP37`

- **Element:** Keycloak
- **Response:** transferred — Single uvicorn/h11 server with no chained proxy in the default deployment; the optional overlay uses maintained oauth2-proxy.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-55 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Keycloak
- **Response:** mitigated — All secrets and session material are CSPRNG-generated (openssl/uuid guidance in .env.example, secrets.token_urlsafe nonces); run ids are sequential but are not credentials.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-57 — Reusing Session IDs (aka Session Replay) - ServerSide  `AC19`

- **Element:** Keycloak
- **Response:** transferred — Session management of Keycloak and OpenCTI is vendor-owned; both are published on loopback only in this deployment.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-60 — Exploit Test APIs  `API01`

- **Element:** Orchestrator API (FastAPI + APScheduler)
- **Response:** mitigated — No test or debug endpoints ship; /docs is the read-only OpenAPI UI and every data route behind it still requires the API key (tests assert 401 without it).
- **pytm mitigations:** Ensure that production systems to not contain sample or test APIs and that these APIs are only used in development environments.

#### F-63 — Privilege Escalation  `AC12`

- **Element:** Orchestrator API (FastAPI + APScheduler)
- **Response:** mitigated — No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-66 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** Orchestrator API (FastAPI + APScheduler)
- **Response:** mitigated — Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-67 — Schema Poisoning  `AC15`

- **Element:** Orchestrator API (FastAPI + APScheduler)
- **Response:** mitigated — STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-73 — Dictionary-based Password Attack  `CR03`

- **Element:** APScheduler cron jobs
- **Response:** transferred — The orchestrator holds no passwords (key-only auth, ADR-005); password policies belong to Keycloak/MISP/OpenCTI vendor auth.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-75 — Privilege Escalation  `AC12`

- **Element:** APScheduler cron jobs
- **Response:** mitigated — No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-77 — Filter Failure through Buffer Overflow  `INP24`

- **Element:** APScheduler cron jobs
- **Response:** mitigated — Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing.
- **pytm mitigations:** Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.

#### F-78 — Schema Poisoning  `AC15`

- **Element:** APScheduler cron jobs
- **Response:** mitigated — STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage.
- **pytm mitigations:** Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

#### F-82 — Audit Log Manipulation  `DE04`

- **Element:** SQLite run store
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007), so tampering is detectable via /targets/{id}/chain/verify; application logs are append-only stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-85 — Audit Log Manipulation  `DE04`

- **Element:** targets.yaml
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007), so tampering is detectable via /targets/{id}/chain/verify; application logs are append-only stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-88 — Audit Log Manipulation  `DE04`

- **Element:** daily_reports (sealed runs)
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007), so tampering is detectable via /targets/{id}/chain/verify; application logs are append-only stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-92 — Dictionary-based Password Attack  `CR03`

- **Element:** SpiderFoot
- **Response:** transferred — The orchestrator holds no passwords (key-only auth, ADR-005); password policies belong to Keycloak/MISP/OpenCTI vendor auth.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-97 — Embedding Scripts within Scripts  `SC03`

- **Element:** SpiderFoot
- **Response:** mitigated — Console CSP is default-src 'none'; script-src/style-src 'self' with hashed build bundles and no inline script (CI checks the built index.html).
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-101 — Removing Important Client Functionality  `SC05`

- **Element:** SpiderFoot
- **Response:** mitigated — CSP base-uri 'none' and frame-ancestors 'none' plus nosniff prevent script-stripping attacks; no security decision lives client-side.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-103 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SpiderFoot
- **Response:** accepted — Static API keys are the documented decision ADR-005; rotation is supported (comma-separated key set, ORCHESTRATOR_SECRET_KEY_PREVIOUS). Installations needing per-user identity deploy the OIDC overlay (ADR-006).
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-108 — XML Attribute Blowup  `INP22`

- **Element:** SpiderFoot
- **Response:** transferred — The orchestrator parses JSON only (no XML/SOAP/DTD anywhere in the API); XML handling, if any, lives in upstream vendor services.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-109 — SOAP Array Overflow  `INP34`

- **Element:** SpiderFoot
- **Response:** transferred — No SOAP stack in the orchestrator; applies only to upstream vendor services.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-111 — HTTP Request Smuggling  `INP37`

- **Element:** SpiderFoot
- **Response:** transferred — Single uvicorn/h11 server with no chained proxy in the default deployment; the optional overlay uses maintained oauth2-proxy.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-112 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SpiderFoot
- **Response:** mitigated — All secrets and session material are CSPRNG-generated (openssl/uuid guidance in .env.example, secrets.token_urlsafe nonces); run ids are sequential but are not credentials.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-117 — Dictionary-based Password Attack  `CR03`

- **Element:** Amass v5 engine
- **Response:** transferred — The orchestrator holds no passwords (key-only auth, ADR-005); password policies belong to Keycloak/MISP/OpenCTI vendor auth.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-120 — Embedding Scripts within Scripts  `SC03`

- **Element:** Amass v5 engine
- **Response:** mitigated — Console CSP is default-src 'none'; script-src/style-src 'self' with hashed build bundles and no inline script (CI checks the built index.html).
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-124 — Removing Important Client Functionality  `SC05`

- **Element:** Amass v5 engine
- **Response:** mitigated — CSP base-uri 'none' and frame-ancestors 'none' plus nosniff prevent script-stripping attacks; no security decision lives client-side.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-126 — Exploitation of Trusted Credentials  `AA03`

- **Element:** Amass v5 engine
- **Response:** accepted — Static API keys are the documented decision ADR-005; rotation is supported (comma-separated key set, ORCHESTRATOR_SECRET_KEY_PREVIOUS). Installations needing per-user identity deploy the OIDC overlay (ADR-006).
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-131 — XML Attribute Blowup  `INP22`

- **Element:** Amass v5 engine
- **Response:** transferred — The orchestrator parses JSON only (no XML/SOAP/DTD anywhere in the API); XML handling, if any, lives in upstream vendor services.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-132 — SOAP Array Overflow  `INP34`

- **Element:** Amass v5 engine
- **Response:** transferred — No SOAP stack in the orchestrator; applies only to upstream vendor services.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-134 — HTTP Request Smuggling  `INP37`

- **Element:** Amass v5 engine
- **Response:** transferred — Single uvicorn/h11 server with no chained proxy in the default deployment; the optional overlay uses maintained oauth2-proxy.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-135 — Session Credential Falsification through Prediction  `AC16`

- **Element:** Amass v5 engine
- **Response:** mitigated — All secrets and session material are CSPRNG-generated (openssl/uuid guidance in .env.example, secrets.token_urlsafe nonces); run ids are sequential but are not credentials.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-140 — Dictionary-based Password Attack  `CR03`

- **Element:** SocialOSINT sidecar
- **Response:** transferred — The orchestrator holds no passwords (key-only auth, ADR-005); password policies belong to Keycloak/MISP/OpenCTI vendor auth.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-143 — Embedding Scripts within Scripts  `SC03`

- **Element:** SocialOSINT sidecar
- **Response:** mitigated — Console CSP is default-src 'none'; script-src/style-src 'self' with hashed build bundles and no inline script (CI checks the built index.html).
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-147 — Removing Important Client Functionality  `SC05`

- **Element:** SocialOSINT sidecar
- **Response:** mitigated — CSP base-uri 'none' and frame-ancestors 'none' plus nosniff prevent script-stripping attacks; no security decision lives client-side.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-149 — Exploitation of Trusted Credentials  `AA03`

- **Element:** SocialOSINT sidecar
- **Response:** accepted — Static API keys are the documented decision ADR-005; rotation is supported (comma-separated key set, ORCHESTRATOR_SECRET_KEY_PREVIOUS). Installations needing per-user identity deploy the OIDC overlay (ADR-006).
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-154 — XML Attribute Blowup  `INP22`

- **Element:** SocialOSINT sidecar
- **Response:** transferred — The orchestrator parses JSON only (no XML/SOAP/DTD anywhere in the API); XML handling, if any, lives in upstream vendor services.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-155 — SOAP Array Overflow  `INP34`

- **Element:** SocialOSINT sidecar
- **Response:** transferred — No SOAP stack in the orchestrator; applies only to upstream vendor services.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-157 — HTTP Request Smuggling  `INP37`

- **Element:** SocialOSINT sidecar
- **Response:** transferred — Single uvicorn/h11 server with no chained proxy in the default deployment; the optional overlay uses maintained oauth2-proxy.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-158 — Session Credential Falsification through Prediction  `AC16`

- **Element:** SocialOSINT sidecar
- **Response:** mitigated — All secrets and session material are CSPRNG-generated (openssl/uuid guidance in .env.example, secrets.token_urlsafe nonces); run ids are sequential but are not credentials.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-160 — Direct Prompt Injection  `LLM01`

- **Element:** Ollama (local models)
- **Response:** mitigated — Collected text reaches models as delimited, flattened untrusted data; replies are schema-validated and invalid items dropped and counted; models have no tools/agents, so injection cannot execute (docs/architecture.md, LLM routing).
- **pytm mitigations:** Implement input content filtering and guardrails. Use prompt engineering techniques to make the system prompt more robust against injection. Apply output validation to detect and block manipulated responses. Monitor and log prompts for anomalous patterns.

#### F-161 — Jailbreaking and Safety Bypass  `LLM07`

- **Element:** Ollama (local models)
- **Response:** accepted — Synthesis is advisory: risk levels are validated against the persisted enum and never drive control flow; a jailbroken reply degrades to a dropped/invalid item, not an action.
- **pytm mitigations:** Implement layered defense with both system prompts and content filtering. Use output filtering to detect and block policy-violating responses. Regularly test with adversarial prompts and update defenses. Consider using classifier models to detect jailbreaking attempts.

#### F-164 — Dictionary-based Password Attack  `CR03`

- **Element:** MISP
- **Response:** transferred — The orchestrator holds no passwords (key-only auth, ADR-005); password policies belong to Keycloak/MISP/OpenCTI vendor auth.
- **pytm mitigations:** Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

#### F-167 — Embedding Scripts within Scripts  `SC03`

- **Element:** MISP
- **Response:** mitigated — Console CSP is default-src 'none'; script-src/style-src 'self' with hashed build bundles and no inline script (CI checks the built index.html).
- **pytm mitigations:** Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

#### F-170 — Removing Important Client Functionality  `SC05`

- **Element:** MISP
- **Response:** mitigated — CSP base-uri 'none' and frame-ancestors 'none' plus nosniff prevent script-stripping attacks; no security decision lives client-side.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-172 — Exploitation of Trusted Credentials  `AA03`

- **Element:** MISP
- **Response:** accepted — Static API keys are the documented decision ADR-005; rotation is supported (comma-separated key set, ORCHESTRATOR_SECRET_KEY_PREVIOUS). Installations needing per-user identity deploy the OIDC overlay (ADR-006).
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-177 — XML Attribute Blowup  `INP22`

- **Element:** MISP
- **Response:** transferred — The orchestrator parses JSON only (no XML/SOAP/DTD anywhere in the API); XML handling, if any, lives in upstream vendor services.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-178 — SOAP Array Overflow  `INP34`

- **Element:** MISP
- **Response:** transferred — No SOAP stack in the orchestrator; applies only to upstream vendor services.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-180 — HTTP Request Smuggling  `INP37`

- **Element:** MISP
- **Response:** transferred — Single uvicorn/h11 server with no chained proxy in the default deployment; the optional overlay uses maintained oauth2-proxy.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-181 — Session Credential Falsification through Prediction  `AC16`

- **Element:** MISP
- **Response:** mitigated — All secrets and session material are CSPRNG-generated (openssl/uuid guidance in .env.example, secrets.token_urlsafe nonces); run ids are sequential but are not credentials.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-183 — Session Sidejacking  `CR01`

- **Element:** OpenCTI platform
- **Response:** accepted — Plaintext session flows are loopback/compose-internal on a trusted host; oauth2-proxy COOKIE_SECURE=false is a local-dev overlay setting — production deployments must set it true behind TLS.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-190 — Removing Important Client Functionality  `SC05`

- **Element:** OpenCTI platform
- **Response:** mitigated — CSP base-uri 'none' and frame-ancestors 'none' plus nosniff prevent script-stripping attacks; no security decision lives client-side.
- **pytm mitigations:** Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

#### F-192 — Exploitation of Trusted Credentials  `AA03`

- **Element:** OpenCTI platform
- **Response:** accepted — Static API keys are the documented decision ADR-005; rotation is supported (comma-separated key set, ORCHESTRATOR_SECRET_KEY_PREVIOUS). Installations needing per-user identity deploy the OIDC overlay (ADR-006).
- **pytm mitigations:** Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

#### F-197 — XML Attribute Blowup  `INP22`

- **Element:** OpenCTI platform
- **Response:** transferred — The orchestrator parses JSON only (no XML/SOAP/DTD anywhere in the API); XML handling, if any, lives in upstream vendor services.
- **pytm mitigations:** This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

#### F-198 — SOAP Array Overflow  `INP34`

- **Element:** OpenCTI platform
- **Response:** transferred — No SOAP stack in the orchestrator; applies only to upstream vendor services.
- **pytm mitigations:** If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

#### F-200 — HTTP Request Smuggling  `INP37`

- **Element:** OpenCTI platform
- **Response:** transferred — Single uvicorn/h11 server with no chained proxy in the default deployment; the optional overlay uses maintained oauth2-proxy.
- **pytm mitigations:** HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.

#### F-201 — Session Credential Falsification through Prediction  `AC16`

- **Element:** OpenCTI platform
- **Response:** mitigated — All secrets and session material are CSPRNG-generated (openssl/uuid guidance in .env.example, secrets.token_urlsafe nonces); run ids are sequential but are not credentials.
- **pytm mitigations:** Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

#### F-203 — Reusing Session IDs (aka Session Replay) - ServerSide  `AC19`

- **Element:** OpenCTI platform
- **Response:** transferred — Session management of Keycloak and OpenCTI is vendor-owned; both are published on loopback only in this deployment.
- **pytm mitigations:** Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

#### F-207 — Audit Log Manipulation  `DE04`

- **Element:** OpenCTI backing stores
- **Response:** mitigated — Run artefacts are HMAC-signed and chained per target (ADR-007), so tampering is detectable via /targets/{id}/chain/verify; application logs are append-only stdout for the operator's shipper.
- **pytm mitigations:** Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

#### F-208 — Session Sidejacking  `CR01`

- **Element:** Operator session (OIDC)
- **Response:** accepted — Plaintext session flows are loopback/compose-internal on a trusted host; oauth2-proxy COOKIE_SECURE=false is a local-dev overlay setting — production deployments must set it true behind TLS.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-212 — Communication Channel Manipulation  `CR06`

- **Element:** Operator session (OIDC)
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-214 — Session Sidejacking  `CR01`

- **Element:** Proxied console/API calls
- **Response:** accepted — Plaintext session flows are loopback/compose-internal on a trusted host; oauth2-proxy COOKIE_SECURE=false is a local-dev overlay setting — production deployments must set it true behind TLS.
- **pytm mitigations:** Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

#### F-218 — Communication Channel Manipulation  `CR06`

- **Element:** Proxied console/API calls
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-221 — Unprotected Sensitive Data  `DR01`

- **Element:** Proxied console/API calls
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-225 — Communication Channel Manipulation  `CR06`

- **Element:** Direct loopback API/console (no overlay)
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-228 — Unprotected Sensitive Data  `DR01`

- **Element:** Direct loopback API/console (no overlay)
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-229 — Credentials Disclosure  `AC23`

- **Element:** Direct loopback API/console (no overlay)
- **Response:** mitigated — Credentials travel only in env/.env (git-ignored), never in logs (parameterized logging, explicit extra fields), and provider keys are sent exclusively over TLS; the console CSP forbids inline script exfiltration.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-233 — Communication Channel Manipulation  `CR06`

- **Element:** GET /health, /metrics
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-238 — Communication Channel Manipulation  `CR06`

- **Element:** POST /bundles (STIX intake)
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-241 — Unprotected Sensitive Data  `DR01`

- **Element:** POST /bundles (STIX intake)
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-242 — Credentials Disclosure  `AC23`

- **Element:** POST /bundles (STIX intake)
- **Response:** mitigated — Credentials travel only in env/.env (git-ignored), never in logs (parameterized logging, explicit extra fields), and provider keys are sent exclusively over TLS; the console CSP forbids inline script exfiltration.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-246 — Communication Channel Manipulation  `CR06`

- **Element:** Cron dispatch (in-process)
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-251 — Communication Channel Manipulation  `CR06`

- **Element:** Scan control & results
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-254 — Unprotected Sensitive Data  `DR01`

- **Element:** Scan control & results
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-258 — Communication Channel Manipulation  `CR06`

- **Element:** Enumeration submit/read (oam_enum/oam_subs)
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-261 — Unprotected Sensitive Data  `DR01`

- **Element:** Enumeration submit/read (oam_enum/oam_subs)
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-265 — Communication Channel Manipulation  `CR06`

- **Element:** Platform collection jobs
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-268 — Unprotected Sensitive Data  `DR01`

- **Element:** Platform collection jobs
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-272 — Communication Channel Manipulation  `CR06`

- **Element:** Due-diligence queries
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-274 — Credentials Disclosure  `AC23`

- **Element:** Due-diligence queries
- **Response:** mitigated — Credentials travel only in env/.env (git-ignored), never in logs (parameterized logging, explicit extra fields), and provider keys are sent exclusively over TLS; the console CSP forbids inline script exfiltration.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-278 — Communication Channel Manipulation  `CR06`

- **Element:** Active reconnaissance
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-283 — Communication Channel Manipulation  `CR06`

- **Element:** Passive collection (OpenOSINT)
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-288 — Communication Channel Manipulation  `CR06`

- **Element:** Qualification & synthesis prompts (local)
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-291 — Unprotected Sensitive Data  `DR01`

- **Element:** Qualification & synthesis prompts (local)
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-295 — Communication Channel Manipulation  `CR06`

- **Element:** Qualification & synthesis prompts (cloud)
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-297 — Credentials Disclosure  `AC23`

- **Element:** Qualification & synthesis prompts (cloud)
- **Response:** mitigated — Credentials travel only in env/.env (git-ignored), never in logs (parameterized logging, explicit extra fields), and provider keys are sent exclusively over TLS; the console CSP forbids inline script exfiltration.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-301 — Communication Channel Manipulation  `CR06`

- **Element:** Run/state SQL
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-304 — Unprotected Sensitive Data  `DR01`

- **Element:** Run/state SQL
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-308 — Communication Channel Manipulation  `CR06`

- **Element:** Seal run artefacts + manifest
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-311 — Unprotected Sensitive Data  `DR01`

- **Element:** Seal run artefacts + manifest
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-315 — Communication Channel Manipulation  `CR06`

- **Element:** Read target inventory
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-320 — Communication Channel Manipulation  `CR06`

- **Element:** STIX ingest (pycti, outbox retries)
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-323 — Unprotected Sensitive Data  `DR01`

- **Element:** STIX ingest (pycti, outbox retries)
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-324 — Credentials Disclosure  `AC23`

- **Element:** STIX ingest (pycti, outbox retries)
- **Response:** mitigated — Credentials travel only in env/.env (git-ignored), never in logs (parameterized logging, explicit extra fields), and provider keys are sent exclusively over TLS; the console CSP forbids inline script exfiltration.
- **pytm mitigations:** Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

#### F-328 — Communication Channel Manipulation  `CR06`

- **Element:** Index/object/queue traffic
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-331 — Unprotected Sensitive Data  `DR01`

- **Element:** Index/object/queue traffic
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

#### F-335 — Communication Channel Manipulation  `CR06`

- **Element:** connector-misp event sync
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-340 — Communication Channel Manipulation  `CR06`

- **Element:** Token redeem / userinfo
- **Response:** mitigated — Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local.
- **pytm mitigations:** Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

#### F-343 — Unprotected Sensitive Data  `DR01`

- **Element:** Token redeem / userinfo
- **Response:** accepted — SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption.
- **pytm mitigations:** All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

### Severity: Medium (177)

#### F-1 — Privilege Abuse  `AC01`

- **Element:** Tavily search API
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-2 — Flooding  `DO01`

- **Element:** Tavily search API
- **Response:** mitigated — Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-5 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Tavily search API
- **Response:** mitigated — Access control is enforced by a router-level dependency plus route tests; the console shell serves only the bundle, never data.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-8 — Manipulate Registry Information  `AC08`

- **Element:** Tavily search API
- **Response:** transferred — No dynamic service registry or DNS-SD: compose service names are static and internal to the trusted network.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-10 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Tavily search API
- **Response:** mitigated — X-Content-Type-Options: nosniff on every console response and asset, plus CSP, remove MIME-confusion XSS.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-12 — Functionality Misuse  `AC09`

- **Element:** Tavily search API
- **Response:** accepted — Run triggers are guarded by the in-progress 409 rule and per-target schedules; retention purge is operator-configured cron.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-13 — XML External Entities Blowup  `INP19`

- **Element:** Tavily search API
- **Response:** transferred — No XML parsing in the orchestrator (JSON-only contract); XXE surface, if any, is upstream.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-14 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Tavily search API
- **Response:** mitigated — Tokens/keys are opaque CSPRNG values; artefact integrity is verifiable through the signed manifest chain (ADR-007).
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-15 — DTD Injection  `INP21`

- **Element:** Tavily search API
- **Response:** transferred — No DTD processing exists in the orchestrator stack.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-18 — HTTP Response Smuggling  `INP36`

- **Element:** Tavily search API
- **Response:** transferred — Same single-server argument as INP37; response smuggling needs a chained proxy this deployment does not have.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-25 — Authentication Abuse/ByPass  `AA01`

- **Element:** oauth2-proxy
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests); /health and /metrics are intentionally open and documented; the public console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-26 — Privilege Abuse  `AC01`

- **Element:** oauth2-proxy
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-27 — Flooding  `DO01`

- **Element:** oauth2-proxy
- **Response:** mitigated — Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-28 — Principal Spoof  `AA02`

- **Element:** oauth2-proxy
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds real authenticated identity where needed (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-30 — Hijacking a privileged process  `AC13`

- **Element:** oauth2-proxy
- **Response:** mitigated — The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-34 — Authentication Abuse/ByPass  `AA01`

- **Element:** Keycloak
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests); /health and /metrics are intentionally open and documented; the public console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-35 — Privilege Abuse  `AC01`

- **Element:** Keycloak
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-36 — Flooding  `DO01`

- **Element:** Keycloak
- **Response:** mitigated — Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-38 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Keycloak
- **Response:** mitigated — Access control is enforced by a router-level dependency plus route tests; the console shell serves only the bundle, never data.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-40 — Principal Spoof  `AA02`

- **Element:** Keycloak
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds real authenticated identity where needed (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-41 — Session Credential Falsification through Forging  `CR04`

- **Element:** Keycloak
- **Response:** transferred — Session token signing/verification belongs to Keycloak and OpenCTI vendor implementations.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-43 — Manipulate Registry Information  `AC08`

- **Element:** Keycloak
- **Response:** transferred — No dynamic service registry or DNS-SD: compose service names are static and internal to the trusted network.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-45 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Keycloak
- **Response:** mitigated — X-Content-Type-Options: nosniff on every console response and asset, plus CSP, remove MIME-confusion XSS.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-47 — Functionality Misuse  `AC09`

- **Element:** Keycloak
- **Response:** accepted — Run triggers are guarded by the in-progress 409 rule and per-target schedules; retention purge is operator-configured cron.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-48 — XML External Entities Blowup  `INP19`

- **Element:** Keycloak
- **Response:** transferred — No XML parsing in the orchestrator (JSON-only contract); XXE surface, if any, is upstream.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-49 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Keycloak
- **Response:** mitigated — Tokens/keys are opaque CSPRNG values; artefact integrity is verifiable through the signed manifest chain (ADR-007).
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-50 — DTD Injection  `INP21`

- **Element:** Keycloak
- **Response:** transferred — No DTD processing exists in the orchestrator stack.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-53 — HTTP Response Smuggling  `INP36`

- **Element:** Keycloak
- **Response:** transferred — Same single-server argument as INP37; response smuggling needs a chained proxy this deployment does not have.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-59 — Authentication Abuse/ByPass  `AA01`

- **Element:** Orchestrator API (FastAPI + APScheduler)
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests); /health and /metrics are intentionally open and documented; the public console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-61 — Flooding  `DO01`

- **Element:** Orchestrator API (FastAPI + APScheduler)
- **Response:** mitigated — Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-62 — Principal Spoof  `AA02`

- **Element:** Orchestrator API (FastAPI + APScheduler)
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds real authenticated identity where needed (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-64 — Hijacking a privileged process  `AC13`

- **Element:** Orchestrator API (FastAPI + APScheduler)
- **Response:** mitigated — The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-70 — Authentication Abuse/ByPass  `AA01`

- **Element:** APScheduler cron jobs
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests); /health and /metrics are intentionally open and documented; the public console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-71 — Privilege Abuse  `AC01`

- **Element:** APScheduler cron jobs
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-72 — Flooding  `DO01`

- **Element:** APScheduler cron jobs
- **Response:** mitigated — Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-74 — Principal Spoof  `AA02`

- **Element:** APScheduler cron jobs
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds real authenticated identity where needed (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-76 — Hijacking a privileged process  `AC13`

- **Element:** APScheduler cron jobs
- **Response:** mitigated — The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack.
- **pytm mitigations:** Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.

#### F-80 — Privilege Abuse  `AC01`

- **Element:** SQLite run store
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-83 — Privilege Abuse  `AC01`

- **Element:** targets.yaml
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-86 — Privilege Abuse  `AC01`

- **Element:** daily_reports (sealed runs)
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-89 — Authentication Abuse/ByPass  `AA01`

- **Element:** SpiderFoot
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests); /health and /metrics are intentionally open and documented; the public console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-90 — Privilege Abuse  `AC01`

- **Element:** SpiderFoot
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-91 — Flooding  `DO01`

- **Element:** SpiderFoot
- **Response:** mitigated — Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-96 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SpiderFoot
- **Response:** mitigated — Access control is enforced by a router-level dependency plus route tests; the console shell serves only the bundle, never data.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-98 — Principal Spoof  `AA02`

- **Element:** SpiderFoot
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds real authenticated identity where needed (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-100 — Manipulate Registry Information  `AC08`

- **Element:** SpiderFoot
- **Response:** transferred — No dynamic service registry or DNS-SD: compose service names are static and internal to the trusted network.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-102 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SpiderFoot
- **Response:** mitigated — X-Content-Type-Options: nosniff on every console response and asset, plus CSP, remove MIME-confusion XSS.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-104 — Functionality Misuse  `AC09`

- **Element:** SpiderFoot
- **Response:** accepted — Run triggers are guarded by the in-progress 409 rule and per-target schedules; retention purge is operator-configured cron.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-105 — XML External Entities Blowup  `INP19`

- **Element:** SpiderFoot
- **Response:** transferred — No XML parsing in the orchestrator (JSON-only contract); XXE surface, if any, is upstream.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-106 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SpiderFoot
- **Response:** mitigated — Tokens/keys are opaque CSPRNG values; artefact integrity is verifiable through the signed manifest chain (ADR-007).
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-107 — DTD Injection  `INP21`

- **Element:** SpiderFoot
- **Response:** transferred — No DTD processing exists in the orchestrator stack.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-110 — HTTP Response Smuggling  `INP36`

- **Element:** SpiderFoot
- **Response:** transferred — Same single-server argument as INP37; response smuggling needs a chained proxy this deployment does not have.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-114 — Authentication Abuse/ByPass  `AA01`

- **Element:** Amass v5 engine
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests); /health and /metrics are intentionally open and documented; the public console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-115 — Privilege Abuse  `AC01`

- **Element:** Amass v5 engine
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-116 — Flooding  `DO01`

- **Element:** Amass v5 engine
- **Response:** mitigated — Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-119 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** Amass v5 engine
- **Response:** mitigated — Access control is enforced by a router-level dependency plus route tests; the console shell serves only the bundle, never data.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-121 — Principal Spoof  `AA02`

- **Element:** Amass v5 engine
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds real authenticated identity where needed (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-123 — Manipulate Registry Information  `AC08`

- **Element:** Amass v5 engine
- **Response:** transferred — No dynamic service registry or DNS-SD: compose service names are static and internal to the trusted network.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-125 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** Amass v5 engine
- **Response:** mitigated — X-Content-Type-Options: nosniff on every console response and asset, plus CSP, remove MIME-confusion XSS.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-127 — Functionality Misuse  `AC09`

- **Element:** Amass v5 engine
- **Response:** accepted — Run triggers are guarded by the in-progress 409 rule and per-target schedules; retention purge is operator-configured cron.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-128 — XML External Entities Blowup  `INP19`

- **Element:** Amass v5 engine
- **Response:** transferred — No XML parsing in the orchestrator (JSON-only contract); XXE surface, if any, is upstream.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-129 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** Amass v5 engine
- **Response:** mitigated — Tokens/keys are opaque CSPRNG values; artefact integrity is verifiable through the signed manifest chain (ADR-007).
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-130 — DTD Injection  `INP21`

- **Element:** Amass v5 engine
- **Response:** transferred — No DTD processing exists in the orchestrator stack.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-133 — HTTP Response Smuggling  `INP36`

- **Element:** Amass v5 engine
- **Response:** transferred — Same single-server argument as INP37; response smuggling needs a chained proxy this deployment does not have.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-137 — Authentication Abuse/ByPass  `AA01`

- **Element:** SocialOSINT sidecar
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests); /health and /metrics are intentionally open and documented; the public console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-138 — Privilege Abuse  `AC01`

- **Element:** SocialOSINT sidecar
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-139 — Flooding  `DO01`

- **Element:** SocialOSINT sidecar
- **Response:** mitigated — Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-142 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** SocialOSINT sidecar
- **Response:** mitigated — Access control is enforced by a router-level dependency plus route tests; the console shell serves only the bundle, never data.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-144 — Principal Spoof  `AA02`

- **Element:** SocialOSINT sidecar
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds real authenticated identity where needed (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-146 — Manipulate Registry Information  `AC08`

- **Element:** SocialOSINT sidecar
- **Response:** transferred — No dynamic service registry or DNS-SD: compose service names are static and internal to the trusted network.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-148 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** SocialOSINT sidecar
- **Response:** mitigated — X-Content-Type-Options: nosniff on every console response and asset, plus CSP, remove MIME-confusion XSS.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-150 — Functionality Misuse  `AC09`

- **Element:** SocialOSINT sidecar
- **Response:** accepted — Run triggers are guarded by the in-progress 409 rule and per-target schedules; retention purge is operator-configured cron.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-151 — XML External Entities Blowup  `INP19`

- **Element:** SocialOSINT sidecar
- **Response:** transferred — No XML parsing in the orchestrator (JSON-only contract); XXE surface, if any, is upstream.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-152 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** SocialOSINT sidecar
- **Response:** mitigated — Tokens/keys are opaque CSPRNG values; artefact integrity is verifiable through the signed manifest chain (ADR-007).
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-153 — DTD Injection  `INP21`

- **Element:** SocialOSINT sidecar
- **Response:** transferred — No DTD processing exists in the orchestrator stack.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-156 — HTTP Response Smuggling  `INP36`

- **Element:** SocialOSINT sidecar
- **Response:** transferred — Same single-server argument as INP37; response smuggling needs a chained proxy this deployment does not have.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-162 — Privilege Abuse  `AC01`

- **Element:** MISP
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-163 — Flooding  `DO01`

- **Element:** MISP
- **Response:** mitigated — Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-166 — Exploiting Incorrectly Configured Access Control Security Levels  `AC07`

- **Element:** MISP
- **Response:** mitigated — Access control is enforced by a router-level dependency plus route tests; the console shell serves only the bundle, never data.
- **pytm mitigations:** Design: Configure the access control correctly.

#### F-169 — Manipulate Registry Information  `AC08`

- **Element:** MISP
- **Response:** transferred — No dynamic service registry or DNS-SD: compose service names are static and internal to the trusted network.
- **pytm mitigations:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

#### F-171 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** MISP
- **Response:** mitigated — X-Content-Type-Options: nosniff on every console response and asset, plus CSP, remove MIME-confusion XSS.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-173 — Functionality Misuse  `AC09`

- **Element:** MISP
- **Response:** accepted — Run triggers are guarded by the in-progress 409 rule and per-target schedules; retention purge is operator-configured cron.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-174 — XML External Entities Blowup  `INP19`

- **Element:** MISP
- **Response:** transferred — No XML parsing in the orchestrator (JSON-only contract); XXE surface, if any, is upstream.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-175 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** MISP
- **Response:** mitigated — Tokens/keys are opaque CSPRNG values; artefact integrity is verifiable through the signed manifest chain (ADR-007).
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-176 — DTD Injection  `INP21`

- **Element:** MISP
- **Response:** transferred — No DTD processing exists in the orchestrator stack.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-179 — HTTP Response Smuggling  `INP36`

- **Element:** MISP
- **Response:** transferred — Same single-server argument as INP37; response smuggling needs a chained proxy this deployment does not have.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-184 — Authentication Abuse/ByPass  `AA01`

- **Element:** OpenCTI platform
- **Response:** mitigated — Every data route depends on require_api_key (401 asserted by tests); /health and /metrics are intentionally open and documented; the public console shell carries no data (ADR-010).
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-185 — Privilege Abuse  `AC01`

- **Element:** OpenCTI platform
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-186 — Flooding  `DO01`

- **Element:** OpenCTI platform
- **Response:** mitigated — Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production.
- **pytm mitigations:** Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

#### F-187 — Principal Spoof  `AA02`

- **Element:** OpenCTI platform
- **Response:** mitigated — Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds real authenticated identity where needed (ADR-006).
- **pytm mitigations:** Employ robust authentication processes (e.g., multi-factor authentication).

#### F-188 — Session Credential Falsification through Forging  `CR04`

- **Element:** OpenCTI platform
- **Response:** transferred — Session token signing/verification belongs to Keycloak and OpenCTI vendor implementations.
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-191 — XSS Using MIME Type Mismatch  `INP17`

- **Element:** OpenCTI platform
- **Response:** mitigated — X-Content-Type-Options: nosniff on every console response and asset, plus CSP, remove MIME-confusion XSS.
- **pytm mitigations:** Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

#### F-193 — Functionality Misuse  `AC09`

- **Element:** OpenCTI platform
- **Response:** accepted — Run triggers are guarded by the in-progress 409 rule and per-target schedules; retention purge is operator-configured cron.
- **pytm mitigations:** Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

#### F-194 — XML External Entities Blowup  `INP19`

- **Element:** OpenCTI platform
- **Response:** transferred — No XML parsing in the orchestrator (JSON-only contract); XXE surface, if any, is upstream.
- **pytm mitigations:** This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

#### F-195 — Session Credential Falsification through Manipulation  `AC11`

- **Element:** OpenCTI platform
- **Response:** mitigated — Tokens/keys are opaque CSPRNG values; artefact integrity is verifiable through the signed manifest chain (ADR-007).
- **pytm mitigations:** Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

#### F-196 — DTD Injection  `INP21`

- **Element:** OpenCTI platform
- **Response:** transferred — No DTD processing exists in the orchestrator stack.
- **pytm mitigations:** Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

#### F-199 — HTTP Response Smuggling  `INP36`

- **Element:** OpenCTI platform
- **Response:** transferred — Same single-server argument as INP37; response smuggling needs a chained proxy this deployment does not have.
- **pytm mitigations:** Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.

#### F-204 — Privilege Abuse  `AC01`

- **Element:** OpenCTI backing stores
- **Response:** accepted — One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

#### F-205 — Shared Data Manipulation  `AC02`

- **Element:** OpenCTI backing stores
- **Response:** transferred — OpenCTI backing stores (Elastic/MinIO/Rabbit/Redis) are owned and hardened by the OpenCTI platform deployment.
- **pytm mitigations:** Use strong authentication and authorization mechanisms. Use HTTPS/SSL for communication.

#### F-209 — Interception  `DE01`

- **Element:** Operator session (OIDC)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-210 — Content Spoofing  `AC05`

- **Element:** Operator session (OIDC)
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-211 — Sniffing Attacks  `DE03`

- **Element:** Operator session (OIDC)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-215 — Interception  `DE01`

- **Element:** Proxied console/API calls
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-216 — Content Spoofing  `AC05`

- **Element:** Proxied console/API calls
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-217 — Sniffing Attacks  `DE03`

- **Element:** Proxied console/API calls
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-219 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Proxied console/API calls
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-222 — Interception  `DE01`

- **Element:** Direct loopback API/console (no overlay)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-223 — Content Spoofing  `AC05`

- **Element:** Direct loopback API/console (no overlay)
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-224 — Sniffing Attacks  `DE03`

- **Element:** Direct loopback API/console (no overlay)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-226 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Direct loopback API/console (no overlay)
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-230 — Interception  `DE01`

- **Element:** GET /health, /metrics
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-231 — Content Spoofing  `AC05`

- **Element:** GET /health, /metrics
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-232 — Sniffing Attacks  `DE03`

- **Element:** GET /health, /metrics
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-234 — Client-Server Protocol Manipulation  `CR08`

- **Element:** GET /health, /metrics
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-235 — Interception  `DE01`

- **Element:** POST /bundles (STIX intake)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-236 — Content Spoofing  `AC05`

- **Element:** POST /bundles (STIX intake)
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-237 — Sniffing Attacks  `DE03`

- **Element:** POST /bundles (STIX intake)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-239 — Client-Server Protocol Manipulation  `CR08`

- **Element:** POST /bundles (STIX intake)
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-243 — Interception  `DE01`

- **Element:** Cron dispatch (in-process)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-244 — Content Spoofing  `AC05`

- **Element:** Cron dispatch (in-process)
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-245 — Sniffing Attacks  `DE03`

- **Element:** Cron dispatch (in-process)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-247 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Cron dispatch (in-process)
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-248 — Interception  `DE01`

- **Element:** Scan control & results
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-249 — Content Spoofing  `AC05`

- **Element:** Scan control & results
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-250 — Sniffing Attacks  `DE03`

- **Element:** Scan control & results
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-252 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Scan control & results
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-255 — Interception  `DE01`

- **Element:** Enumeration submit/read (oam_enum/oam_subs)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-256 — Content Spoofing  `AC05`

- **Element:** Enumeration submit/read (oam_enum/oam_subs)
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-257 — Sniffing Attacks  `DE03`

- **Element:** Enumeration submit/read (oam_enum/oam_subs)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-259 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Enumeration submit/read (oam_enum/oam_subs)
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-262 — Interception  `DE01`

- **Element:** Platform collection jobs
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-263 — Content Spoofing  `AC05`

- **Element:** Platform collection jobs
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-264 — Sniffing Attacks  `DE03`

- **Element:** Platform collection jobs
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-266 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Platform collection jobs
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-269 — Interception  `DE01`

- **Element:** Due-diligence queries
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-270 — Content Spoofing  `AC05`

- **Element:** Due-diligence queries
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-271 — Sniffing Attacks  `DE03`

- **Element:** Due-diligence queries
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-275 — Interception  `DE01`

- **Element:** Active reconnaissance
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-276 — Content Spoofing  `AC05`

- **Element:** Active reconnaissance
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-277 — Sniffing Attacks  `DE03`

- **Element:** Active reconnaissance
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-280 — Interception  `DE01`

- **Element:** Passive collection (OpenOSINT)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-281 — Content Spoofing  `AC05`

- **Element:** Passive collection (OpenOSINT)
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-282 — Sniffing Attacks  `DE03`

- **Element:** Passive collection (OpenOSINT)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-285 — Interception  `DE01`

- **Element:** Qualification & synthesis prompts (local)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-286 — Content Spoofing  `AC05`

- **Element:** Qualification & synthesis prompts (local)
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-287 — Sniffing Attacks  `DE03`

- **Element:** Qualification & synthesis prompts (local)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-289 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Qualification & synthesis prompts (local)
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-292 — Interception  `DE01`

- **Element:** Qualification & synthesis prompts (cloud)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-293 — Content Spoofing  `AC05`

- **Element:** Qualification & synthesis prompts (cloud)
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-294 — Sniffing Attacks  `DE03`

- **Element:** Qualification & synthesis prompts (cloud)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-298 — Interception  `DE01`

- **Element:** Run/state SQL
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-299 — Content Spoofing  `AC05`

- **Element:** Run/state SQL
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-300 — Sniffing Attacks  `DE03`

- **Element:** Run/state SQL
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-302 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Run/state SQL
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-305 — Interception  `DE01`

- **Element:** Seal run artefacts + manifest
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-306 — Content Spoofing  `AC05`

- **Element:** Seal run artefacts + manifest
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-307 — Sniffing Attacks  `DE03`

- **Element:** Seal run artefacts + manifest
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-309 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Seal run artefacts + manifest
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-312 — Interception  `DE01`

- **Element:** Read target inventory
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-313 — Content Spoofing  `AC05`

- **Element:** Read target inventory
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-314 — Sniffing Attacks  `DE03`

- **Element:** Read target inventory
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-316 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Read target inventory
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-317 — Interception  `DE01`

- **Element:** STIX ingest (pycti, outbox retries)
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-318 — Content Spoofing  `AC05`

- **Element:** STIX ingest (pycti, outbox retries)
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-319 — Sniffing Attacks  `DE03`

- **Element:** STIX ingest (pycti, outbox retries)
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-321 — Client-Server Protocol Manipulation  `CR08`

- **Element:** STIX ingest (pycti, outbox retries)
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-325 — Interception  `DE01`

- **Element:** Index/object/queue traffic
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-326 — Content Spoofing  `AC05`

- **Element:** Index/object/queue traffic
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-327 — Sniffing Attacks  `DE03`

- **Element:** Index/object/queue traffic
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-329 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Index/object/queue traffic
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

#### F-332 — Interception  `DE01`

- **Element:** connector-misp event sync
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-333 — Content Spoofing  `AC05`

- **Element:** connector-misp event sync
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-334 — Sniffing Attacks  `DE03`

- **Element:** connector-misp event sync
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-337 — Interception  `DE01`

- **Element:** Token redeem / userinfo
- **Response:** accepted — Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS.
- **pytm mitigations:** Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

#### F-338 — Content Spoofing  `AC05`

- **Element:** Token redeem / userinfo
- **Response:** mitigated — Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served.
- **pytm mitigations:** Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

#### F-339 — Sniffing Attacks  `DE03`

- **Element:** Token redeem / userinfo
- **Response:** accepted — Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope.
- **pytm mitigations:** Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

#### F-341 — Client-Server Protocol Manipulation  `CR08`

- **Element:** Token redeem / userinfo
- **Response:** mitigated — Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model.
- **pytm mitigations:** Use strong authentication protocols.

### Severity: Low (12)

#### F-7 — Encryption Brute Forcing  `CR05`

- **Element:** Tavily search API
- **Response:** mitigated — Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-42 — Encryption Brute Forcing  `CR05`

- **Element:** Keycloak
- **Response:** mitigated — Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-81 — Encryption Brute Forcing  `CR05`

- **Element:** SQLite run store
- **Response:** mitigated — Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-84 — Encryption Brute Forcing  `CR05`

- **Element:** targets.yaml
- **Response:** mitigated — Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-87 — Encryption Brute Forcing  `CR05`

- **Element:** daily_reports (sealed runs)
- **Response:** mitigated — Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-95 — Web Application Fingerprinting  `HA03`

- **Element:** SpiderFoot
- **Response:** accepted — SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself.
- **pytm mitigations:** Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.

#### F-99 — Encryption Brute Forcing  `CR05`

- **Element:** SpiderFoot
- **Response:** mitigated — Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-122 — Encryption Brute Forcing  `CR05`

- **Element:** Amass v5 engine
- **Response:** mitigated — Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-145 — Encryption Brute Forcing  `CR05`

- **Element:** SocialOSINT sidecar
- **Response:** mitigated — Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-168 — Encryption Brute Forcing  `CR05`

- **Element:** MISP
- **Response:** mitigated — Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-189 — Encryption Brute Forcing  `CR05`

- **Element:** OpenCTI platform
- **Response:** mitigated — Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

#### F-206 — Encryption Brute Forcing  `CR05`

- **Element:** OpenCTI backing stores
- **Response:** mitigated — Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible.
- **pytm mitigations:** Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.

### Severity: Very Low (1)

#### F-93 — Footprinting  `DS03`

- **Element:** SpiderFoot
- **Response:** accepted — Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments.
- **pytm mitigations:** Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.
