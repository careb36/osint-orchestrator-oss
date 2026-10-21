"""
OWASP pytm threat model of the OSINT Orchestrator.

Model source of truth: docs/architecture.md, docs/adr/ (001-011),
docker-compose*.yml, orchestrator/config.py and orchestrator/auth.py.

pytm is a modelling tool, not a runtime dependency of the service: it lives in
a throwaway virtualenv and never in pyproject.toml (see docs/operations.md,
"Threat model"). Regenerate the report with:

    python3 -m venv .venv-pytm
    .venv-pytm/bin/pip install pytm==1.4.0
    .venv-pytm/bin/python scripts/threat_model.py

The script writes docs/threat-model.md and fails if any fired threat lacks a
triage entry, so the report never carries an unaddressed finding. Controls
mirror what the codebase actually implements; deliberate gaps (loopback HTTP,
unauthenticated SpiderFoot, no encryption at rest, static long-lived keys,
MISP cert verify off in dev) are left open on purpose so they surface as
findings and carry an explicit accepted response.
"""

from pathlib import Path

try:
    import pytm
    from pytm import (
        Actor,
        Boundary,
        Classification,
        Controls,
        Data,
        Dataflow,
        Datastore,
        ExternalEntity,
        Lifetime,
        LLM,
        Process,
        Server,
        TLSVersion,
        TM,
    )
except ModuleNotFoundError as exc:  # pragma: no cover - tool venv missing
    raise SystemExit(
        "pytm is not installed in this interpreter. Create the tool venv and pin it:\n"
        "    python3 -m venv .venv-pytm && .venv-pytm/bin/pip install pytm==1.4.0\n"
        "    .venv-pytm/bin/python scripts/threat_model.py"
    ) from exc

tm = TM("OSINT Orchestrator")
tm.description = (
    "Modular monolith (ADR-001): one FastAPI process with an in-process APScheduler and a "
    "SQLite store drives OSINT collectors, qualifies evidence with an LLM, normalises findings "
    "to STIX 2.1 (ADR-002), ingests them into OpenCTI (ADR-003/008), seals a signed report chain "
    "per run (ADR-007) and dispatches alerts. Access uses static API keys and a single instance "
    "(ADR-005), with an optional OIDC proxy perimeter (ADR-006) and an external STIX intake "
    "(ADR-011). Operator prose is Spanish, code English (ADR-004)."
)
tm.assumptions = [
    "Single-instance deployment on a trusted Docker host; loopback-published ports are reachable only from that host.",
    "The Docker host and the compose network are operated by the same team as the orchestrator.",
    "Collectors only query targets authorised in targets.yaml (operator attestation per target).",
    "OpenCTI, MISP and the OIDC overlay are optional deployments; the model covers them when enabled.",
]


def C(**kw) -> Controls:
    """Baseline hardening every managed component of this codebase actually ships."""
    base = dict(
        isHardened=True,  # containers run as uid 1000, no root, pinned images
        definesConnectionTimeout=True,  # *_TIMEOUT_SECONDS on every client
        handlesResourceConsumption=True,  # per-run ceilings: TAVILY_MAX_CALLS_PER_RUN, LLM_QUALIFY_MAX_ITEMS
        handlesInterruptions=True,  # outbox + retry queues (OpenCTI, alerts)
        handlesCrashes=True,  # restart policy + APScheduler misfire grace
        implementsServerSideValidation=True,  # pydantic models on every route body
        validatesInput=True,
        sanitizesInput=True,  # collected text reaches models delimited and flattened
        validatesHeaders=True,
        validatesContentType=True,
        encodesOutput=True,  # React escaping + strict CSP, no inline script
        disablesDTD=True,
        disablesiFrames=True,  # CSP frame-ancestors 'none'
        usesSecureFunctions=True,
        tracksExecutionFlow=True,
    )
    base.update(kw)
    return Controls(**base)


# ── Boundaries ──────────────────────────────────────────────────────────────
internet = Boundary("Public Internet")
edge = Boundary("OIDC edge (optional, ADR-006)")
compose = Boundary("Docker compose network (trusted host)")
opencti_b = Boundary("OpenCTI platform (separate admin domain)")

# ── Data assets ─────────────────────────────────────────────────────────────
api_key = Data(
    name="ORCHESTRATOR_API_KEY",
    description="Static operator API key, comma-separated rotation set (ADR-005).",
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
evidence = Data(
    name="Qualified evidence & STIX bundle",
    description="Collector output qualified by the LLM, normalised to STIX 2.1; untrusted web text inside.",
    classification=Classification.RESTRICTED,
    isStored=True,
    isDestEncryptedAtRest=False,
)
run_artefacts = Data(
    name="Sealed run artefacts",
    description="report.md, bundle, delta, evidence and the HMAC-signed manifest chain (ADR-007).",
    classification=Classification.RESTRICTED,
    isStored=True,
    isDestEncryptedAtRest=False,
)
operator_session = Data(
    name="oauth2-proxy session cookie",
    description="OIDC session of the operator behind the optional proxy.",
    isCredentials=True,
    credentialsLife=Lifetime.SHORT,
    classification=Classification.SECRET,
)
prompts = Data(
    name="LLM prompts with collected text",
    description="Flattened, delimited untrusted collector text plus entity context sent to a model.",
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

tavily = Server("Tavily search API")
tavily.inBoundary = internet
tavily.controls = C(isEncrypted=True, authenticatesSource=True)

cloud_llm = LLM("Cloud LLM provider")
cloud_llm.inBoundary = internet
cloud_llm.isThirdParty = True
cloud_llm.controls = C(isEncrypted=True, authenticatesSource=True)

# ── OIDC edge (optional overlay) ────────────────────────────────────────────
proxy = Process("oauth2-proxy")
proxy.inBoundary = edge
proxy.controls = C(
    implementsAuthenticationScheme=True,
    authenticationScheme="OIDC authorization code (Keycloak)",
    encryptsCookies=False,  # AUTH_PROXY_COOKIE_SECURE=false in the local-dev overlay
    usesStrongSessionIdentifiers=True,
    implementsCSRFToken=True,
    verifySessionIdentifiers=True,
    isEncrypted=True,
)

keycloak = Server("Keycloak")
keycloak.inBoundary = edge
keycloak.usesSessionTokens = True
keycloak.controls = C(
    isEncryptedAtRest=False,
    implementsAuthenticationScheme=True,
    authenticationScheme="realm users; bootstrap admin on first boot",
    usesMFA=False,
)

# ── Orchestrator (compose network) ──────────────────────────────────────────
orchestrator = Process("Orchestrator API (FastAPI + APScheduler)")
orchestrator.inBoundary = compose
orchestrator.implementsAPI = True
orchestrator.usesEnvironmentVariables = True
orchestrator.handlesResources = True
orchestrator.controls = C(
    hasAccessControl=True,
    implementsAuthenticationScheme=True,
    authenticationScheme="static X-API-Key / Bearer (ADR-005)",
    authorizesSource=True,
    implementsStrictHTTPValidation=True,
    providesIntegrity=True,  # HMAC-signed manifest chain, ADR-007
    usesCodeSigning=True,
    implementsPOLP=False,  # one operator key, no per-user roles (ADR-005)
    usesMFA=False,
)

scheduler = Process("APScheduler cron jobs")
scheduler.inBoundary = compose
scheduler.description = "In-process scheduler: target crons, outbox and alert retries, retention purge."
scheduler.controls = C(hasAccessControl=True)

sqlite = Datastore("SQLite run store")
sqlite.inBoundary = compose
sqlite.isSQL = True
sqlite.controls = C(
    isEncryptedAtRest=False,  # genuine gap: volume-backed plaintext SQLite
    providesIntegrity=True,
    usesParameterizedInput=True,  # SQLModel / SQLAlchemy ORM
)

targets_yaml = Datastore("targets.yaml")
targets_yaml.inBoundary = compose
targets_yaml.description = "Target inventory, schedules and per-target authorisation; mounted read-only."
targets_yaml.hasWriteAccess = False
targets_yaml.controls = C(isEncryptedAtRest=False, providesIntegrity=True)

reports = Datastore("daily_reports (sealed runs)")
reports.inBoundary = compose
reports.controls = C(isEncryptedAtRest=False, providesIntegrity=True)  # signed chain, plaintext files

spiderfoot = Server("SpiderFoot")
spiderfoot.inBoundary = compose
spiderfoot.description = "Built from a pinned commit; web UI and API without authentication, loopback only."
spiderfoot.controls = C(isHardened=False, isEncrypted=False, authenticatesSource=False, hasAccessControl=False)

amass = Server("Amass v5 engine")
amass.inBoundary = compose
amass.controls = C(isEncrypted=False, authenticatesSource=False, hasAccessControl=False)

socialosint = Server("SocialOSINT sidecar")
socialosint.inBoundary = compose
socialosint.controls = C(isEncrypted=False, authenticatesSource=False, hasAccessControl=False)

ollama = LLM("Ollama (local models)")
ollama.inBoundary = compose
ollama.isThirdParty = False
ollama.controls = C(isEncrypted=False, authenticatesSource=False)

misp = Server("MISP")
misp.inBoundary = compose
misp.controls = C(
    isEncrypted=True,
    authenticatesSource=True,
    authenticationScheme="MISP API key",
    checksDestinationRevocation=False,  # MISP_SSL_VERIFY=false in local dev
)

# ── OpenCTI platform ────────────────────────────────────────────────────────
opencti = Server("OpenCTI platform")
opencti.inBoundary = opencti_b
opencti.usesSessionTokens = True
opencti.controls = C(
    hasAccessControl=True,
    implementsAuthenticationScheme=True,
    authenticationScheme="admin token / GraphQL session",
    isEncrypted=False,  # compose-internal HTTP
)

opencti_store = Datastore("OpenCTI backing stores")
opencti_store.inBoundary = opencti_b
opencti_store.description = "Elasticsearch indices, MinIO objects, RabbitMQ queues, Redis."
opencti_store.isShared = True
opencti_store.controls = C(isEncryptedAtRest=False)

# ── Dataflows ───────────────────────────────────────────────────────────────
Dataflow(operator, proxy, "Operator session (OIDC)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
         usesSessionTokens=True, data=[operator_session],
         controls=C(isEncrypted=True, authenticatesDestination=True))
Dataflow(proxy, orchestrator, "Proxied console/API calls", protocol="HTTP", tlsVersion=TLSVersion.NONE,
         usesSessionTokens=True, data=[operator_session],
         controls=C(isEncrypted=False, authenticatesSource=True))
Dataflow(operator, orchestrator, "Direct loopback API/console (no overlay)", protocol="HTTP", tlsVersion=TLSVersion.NONE,
         data=[api_key], controls=C(isEncrypted=False, authenticatesSource=True))
Dataflow(anonymous, orchestrator, "GET /health, /metrics", protocol="HTTP", tlsVersion=TLSVersion.NONE,
         controls=C(isEncrypted=False, authenticatesSource=False, hasAccessControl=False))
Dataflow(stix_producer, orchestrator, "POST /bundles (STIX intake)", protocol="HTTP", tlsVersion=TLSVersion.NONE,
         data=[api_key, evidence],
         controls=C(isEncrypted=False, authenticatesSource=True, validatesInput=True))
Dataflow(scheduler, orchestrator, "Cron dispatch (in-process)", protocol="inproc",
         controls=C(authenticatesSource=True))
Dataflow(orchestrator, spiderfoot, "Scan control & results", protocol="HTTP", tlsVersion=TLSVersion.NONE,
         data=[evidence], controls=C(isEncrypted=False, authenticatesDestination=False))
Dataflow(orchestrator, amass, "Enumeration submit/read (oam_enum/oam_subs)", protocol="HTTP", tlsVersion=TLSVersion.NONE,
         data=[evidence], controls=C(isEncrypted=False, authenticatesDestination=False))
Dataflow(orchestrator, socialosint, "Platform collection jobs", protocol="HTTP", tlsVersion=TLSVersion.NONE,
         data=[evidence], controls=C(isEncrypted=False, authenticatesDestination=False))
Dataflow(orchestrator, tavily, "Due-diligence queries", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
         data=[llm_key], controls=C(isEncrypted=True, authenticatesDestination=True))
Dataflow(spiderfoot, public_web, "Active reconnaissance", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
         data=[evidence], controls=C(isEncrypted=True))
Dataflow(orchestrator, public_web, "Passive collection (OpenOSINT)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
         data=[evidence], controls=C(isEncrypted=True))
Dataflow(orchestrator, ollama, "Qualification & synthesis prompts (local)", protocol="HTTP", tlsVersion=TLSVersion.NONE,
         data=[prompts], controls=C(isEncrypted=False, authenticatesDestination=False))
Dataflow(orchestrator, cloud_llm, "Qualification & synthesis prompts (cloud)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
         data=[prompts, llm_key], controls=C(isEncrypted=True, authenticatesDestination=True))
Dataflow(orchestrator, sqlite, "Run/state SQL", protocol="SQL", data=[evidence],
         controls=C(isEncrypted=False, usesParameterizedInput=True, providesIntegrity=True))
Dataflow(orchestrator, reports, "Seal run artefacts + manifest", protocol="file", data=[run_artefacts],
         controls=C(isEncrypted=False, providesIntegrity=True))
Dataflow(orchestrator, targets_yaml, "Read target inventory", protocol="file",
         controls=C(isEncrypted=False, providesIntegrity=True))
Dataflow(orchestrator, opencti, "STIX ingest (pycti, outbox retries)", protocol="HTTP", tlsVersion=TLSVersion.NONE,
         data=[opencti_token, evidence], controls=C(isEncrypted=False, authenticatesDestination=True))
Dataflow(opencti, opencti_store, "Index/object/queue traffic", protocol="HTTP", tlsVersion=TLSVersion.NONE,
         data=[evidence], controls=C(isEncrypted=False))
Dataflow(misp, opencti, "connector-misp event sync", protocol="HTTPS", tlsVersion=TLSVersion.TLSv12,
         data=[evidence],
         controls=C(isEncrypted=True, authenticatesDestination=True, checksDestinationRevocation=False))
Dataflow(proxy, keycloak, "Token redeem / userinfo", protocol="HTTP", tlsVersion=TLSVersion.NONE,
         data=[operator_session], controls=C(isEncrypted=False, authenticatesDestination=True))

# ── Resolve & triage ────────────────────────────────────────────────────────
# Every fired threat gets an explicit response (pytm Finding.response):
#   mitigated   → a control in this codebase already addresses it (cite where)
#   transferred → the risk lives in a vendor/upstream component we consume
#   accepted    → documented decision (ADR / local-dev scope) with a hardening note
# Nothing is left untriaged: an unmapped threat id would fail the run.
TRIAGE: dict[str, tuple[str, str]] = {
    # ── Very High ──
    "AC06": ("mitigated", "Collectors return structured CollectorResult; raw tool output never leaves the collector module (docs/architecture.md). Artefacts are never executed; the console renders escaped text under CSP default-src 'none'."),
    "AC14": ("mitigated", "The pipeline isolates every step (collect/qualify/normalise/synthesise/seal/alert): a raised error fails the run, never a privileged transaction; the process runs as uid 1000 with no setuid paths (Dockerfile)."),
    "AC17": ("accepted", "Sidecars and vendor servers sit on the trusted compose network or loopback only (ADR-005 single host). Hardening for shared hosts: network policies + TLS between services."),
    "AC21": ("mitigated", "Data routes authenticate with the X-API-Key/Bearer header, never cookies, so there is no cookie to forge cross-site; the console CSP sets form-action 'none'; the OIDC overlay implements CSRF tokens (oauth2-proxy)."),
    "DS06": ("mitigated", "Every flow that crosses the host boundary uses TLS 1.2+; plaintext flows (loopback ports, compose bridge, in-process) never leave the trusted Docker host (ADR-005). Keys live only in .env (git-ignored) and environment variables."),
    "INP02": ("mitigated", "Memory-safe runtime (Python) with no manual buffer handling; inputs are bounded by validation (Query ge/le), list caps (LLM_QUALIFY_MAX_ITEMS, TAVILY_MAX_RESULTS, PAGE) and LLM_MAX_OBSERVABLES_IN_PROMPT."),
    # ── High ──
    "AA03": ("accepted", "Static API keys are the documented decision ADR-005; rotation is supported (comma-separated key set, ORCHESTRATOR_SECRET_KEY_PREVIOUS). Installations needing per-user identity deploy the OIDC overlay (ADR-006)."),
    "AC12": ("mitigated", "No privilege separation exists inside the monolith (ADR-001): the container runs as uid 1000, targets.yaml is mounted read-only, and the API exposes a single operator role, so there is no higher privilege to escalate to."),
    "AC15": ("mitigated", "STIX 2.1 objects are built only in orchestrator/normalizer/stix.py with deterministic ids; inbound bundles are contract-validated (ADR-011) and model replies are JSON-schema validated before storage."),
    "AC16": ("mitigated", "All secrets and session material are CSPRNG-generated (openssl/uuid guidance in .env.example, secrets.token_urlsafe nonces); run ids are sequential but are not credentials."),
    "AC19": ("transferred", "Session management of Keycloak and OpenCTI is vendor-owned; both are published on loopback only in this deployment."),
    "AC23": ("mitigated", "Credentials travel only in env/.env (git-ignored), never in logs (parameterized logging, explicit extra fields), and provider keys are sent exclusively over TLS; the console CSP forbids inline script exfiltration."),
    "API01": ("mitigated", "No test or debug endpoints ship; /docs is the read-only OpenAPI UI and every data route behind it still requires the API key (tests assert 401 without it)."),
    "CR01": ("accepted", "Plaintext session flows are loopback/compose-internal on a trusted host; oauth2-proxy COOKIE_SECURE=false is a local-dev overlay setting — production deployments must set it true behind TLS."),
    "CR03": ("transferred", "The orchestrator holds no passwords (key-only auth, ADR-005); password policies belong to Keycloak/MISP/OpenCTI vendor auth."),
    "CR06": ("mitigated", "Supply channel is pinned (git deps by 40-char SHA, images by explicit tag, never :latest); internet flows are TLS; internal channels are host-local."),
    "DE04": ("mitigated", "Run artefacts are HMAC-signed and chained per target (ADR-007), so tampering is detectable via /targets/{id}/chain/verify; application logs are append-only stdout for the operator's shipper."),
    "DR01": ("accepted", "SQLite and daily_reports are plaintext at rest by design on a single trusted host (ADR-005). Hardening for shared infrastructure: encrypted volumes/disk encryption."),
    "INP22": ("transferred", "The orchestrator parses JSON only (no XML/SOAP/DTD anywhere in the API); XML handling, if any, lives in upstream vendor services."),
    "INP24": ("mitigated", "Bounded query parameters (ge/le), capped result lists and per-run budgets (LLM_TIMEOUT_SECONDS, TAVILY_MAX_CALLS_PER_RUN) prevent unbounded filter processing."),
    "INP34": ("transferred", "No SOAP stack in the orchestrator; applies only to upstream vendor services."),
    "INP37": ("transferred", "Single uvicorn/h11 server with no chained proxy in the default deployment; the optional overlay uses maintained oauth2-proxy."),
    "LLM01": ("mitigated", "Collected text reaches models as delimited, flattened untrusted data; replies are schema-validated and invalid items dropped and counted; models have no tools/agents, so injection cannot execute (docs/architecture.md, LLM routing)."),
    "LLM07": ("accepted", "Synthesis is advisory: risk levels are validated against the persisted enum and never drive control flow; a jailbroken reply degrades to a dropped/invalid item, not an action."),
    "SC03": ("mitigated", "Console CSP is default-src 'none'; script-src/style-src 'self' with hashed build bundles and no inline script (CI checks the built index.html)."),
    "SC05": ("mitigated", "CSP base-uri 'none' and frame-ancestors 'none' plus nosniff prevent script-stripping attacks; no security decision lives client-side."),
    # ── Medium ─
    "AA01": ("mitigated", "Every data route depends on require_api_key (401 asserted by tests); /health and /metrics are intentionally open and documented; the public console shell carries no data (ADR-010)."),
    "AA02": ("mitigated", "Identity is proven per request by the shared secret, never self-asserted; the OIDC overlay adds real authenticated identity where needed (ADR-006)."),
    "AC01": ("accepted", "One operator role by design (ADR-005/010: no users or roles); alert acknowledgements record the operator-supplied name as an audit hint, not an authorization."),
    "AC02": ("transferred", "OpenCTI backing stores (Elastic/MinIO/Rabbit/Redis) are owned and hardened by the OpenCTI platform deployment."),
    "AC05": ("mitigated", "Operator text is localised (ADR-004) and rendered escaped by React; reports render as monospace pre blocks; no user-controlled HTML is ever served."),
    "AC07": ("mitigated", "Access control is enforced by a router-level dependency plus route tests; the console shell serves only the bundle, never data."),
    "AC08": ("transferred", "No dynamic service registry or DNS-SD: compose service names are static and internal to the trusted network."),
    "AC09": ("accepted", "Run triggers are guarded by the in-progress 409 rule and per-target schedules; retention purge is operator-configured cron."),
    "AC11": ("mitigated", "Tokens/keys are opaque CSPRNG values; artefact integrity is verifiable through the signed manifest chain (ADR-007)."),
    "AC13": ("mitigated", "The single process runs unprivileged (uid 1000) with no privilege-drop window to hijack."),
    "CR04": ("transferred", "Session token signing/verification belongs to Keycloak and OpenCTI vendor implementations."),
    "CR08": ("mitigated", "Strict HTTP and content-type validation on the API; each flow pins its protocol and TLS version in this model."),
    "DE01": ("accepted", "Host-internal plaintext flows (loopback, compose bridge, in-process) are within the trusted boundary of ADR-005; everything external is TLS."),
    "DE03": ("accepted", "Same boundary argument as DE01: sniffing requires host compromise, which is out of the modeled scope."),
    "DO01": ("mitigated", "Single instance by design (ADR-005) with concurrency guards (409 on active run), retry budgets and per-run call caps; rate limiting is an overlay/proxy concern in production."),
    "INP17": ("mitigated", "X-Content-Type-Options: nosniff on every console response and asset, plus CSP, remove MIME-confusion XSS."),
    "INP19": ("transferred", "No XML parsing in the orchestrator (JSON-only contract); XXE surface, if any, is upstream."),
    "INP21": ("transferred", "No DTD processing exists in the orchestrator stack."),
    "INP36": ("transferred", "Same single-server argument as INP37; response smuggling needs a chained proxy this deployment does not have."),
    # ── Low / Very Low ──
    "CR05": ("mitigated", "Keys and HMACs use 128-256-bit CSPRNG material (openssl rand guidance) and SHA-256 chaining; brute force is infeasible."),
    "HA03": ("accepted", "SpiderFoot's unauthenticated UI is upstream design; compose publishes it on loopback only, limiting fingerprinting to the host itself."),
    "DS03": ("accepted", "Footprinting of the loopback-only SpiderFoot service yields no external surface; documented in compose comments."),
}

tm.resolve()
findings = tm.findings

unmapped = sorted({f.threat_id for f in findings} - set(TRIAGE))
if unmapped:
    raise SystemExit(f"Untriaged threats (add them to TRIAGE): {unmapped}")

for f in findings:
    f.response, f.triage_note = TRIAGE[f.threat_id]

out = Path(__file__).resolve().parents[1] / "docs" / "threat-model.md"
by_sev: dict[str, list] = {}
for f in findings:
    by_sev.setdefault(str(getattr(f, "severity", "") or "unrated"), []).append(f)
by_resp: dict[str, list] = {}
for f in findings:
    by_resp.setdefault(f.response, []).append(f)

lines = [
    f"# Threat model — OSINT Orchestrator (OWASP pytm, threat library 114 threats)",
    "",
    tm.description,
    "",
    "## Assumptions",
    "",
    *[f"- {a}" for a in tm.assumptions],
    "",
    f"## Findings: {len(findings)} across {len({f.threat_id for f in findings})} distinct threats",
    "",
    "Every finding carries a triage response:",
    "",
    *[f"- **{resp}**: {len(group)} finding(s)" for resp, group in sorted(by_resp.items())],
    "",
    "## Triage summary by threat",
    "",
    "| Threat | Severity | Response | Rationale |",
    "| --- | --- | --- | --- |",
]
seen: dict[str, tuple] = {}
for f in findings:
    seen.setdefault(f.threat_id, (f.severity, f.response, f.triage_note, f.description))
for tid in sorted(seen):
    sev, resp, note, desc = seen[tid]
    lines.append(f"| {tid} {desc} | {sev} | {resp} | {note} |")

lines += ["", "## Full findings", ""]
order = {"very high": 0, "high": 1, "medium": 2, "low": 3, "very low": 4}
for sev in sorted(by_sev, key=lambda s: order.get(s.lower(), 9)):
    group = by_sev[sev]
    lines += [f"### Severity: {sev} ({len(group)})", ""]
    for f in sorted(group, key=lambda x: int(x.id)):
        lines += [
            f"#### F-{f.id} — {f.description}  `{f.threat_id}`",
            "",
            f"- **Element:** {f.target}",
            f"- **Response:** {f.response} — {f.triage_note}",
        ]
        if getattr(f, "mitigations", ""):
            lines.append(f"- **pytm mitigations:** {f.mitigations}")
        lines.append("")
out.write_text("\n".join(lines), encoding="utf-8")

print(f"findings: {len(findings)}")
for sev in sorted(by_sev, key=lambda s: order.get(s.lower(), 9)):
    print(f"  {sev}: {len(by_sev[sev])}")
print("triage:")
for resp, group in sorted(by_resp.items()):
    print(f"  {resp}: {len(group)}")
print(f"report: {out}")
