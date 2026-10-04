# Executive Presentation: OSINT Orchestrator for Continuous Monitoring

> 🇪🇸 [Español](presentacion-ejecutiva-orquestacion-osint.es.md)

**Last reviewed:** 2026-09-17
**Audience:** Management, Accounting, AML/CTF Compliance, Legal.
**Document type:** Explanation (Diátaxis) — not an operations manual.

> **Scope and disclaimer.** This document describes a support tool for due
> diligence and monitoring processes. **It is not legal advice**, it does not
> replace the professional judgement of the Compliance Officer or the
> Accounting team, and it does not waive any obligation under Uruguayan
> anti-money-laundering and counter-terrorist-financing (AML/CTF) regulation.

---

## 1) Executive summary

The **OSINT Orchestrator** project automates the orderly collection of
open-source intelligence (OSINT) about authorised digital assets — for
example, a company's web domain — and turns it into traceable, dated,
auditable evidence.

In one sentence: **the system continuously and provably watches what an
analyst would otherwise watch by hand, and keeps a record of everything it
saw, when, and under whose authorisation.**

- **Problem it solves:** due diligence and continuous monitoring are done
  manually today — scattered across analysts and hard to evidence in an audit
  or before the supervisor.
- **What it delivers:** scheduled runs, findings normalised to an
  international standard (STIX 2.1), a single repository of findings
  (OpenCTI), daily reports, alerts, and a full audit trail per run.
- **What it needs:** a host with ≥16 GB RAM, a list of authorised targets,
  and a 15–20 minute daily review routine (operator manuals already written
  for accounting and legal teams).
- **Licence cost:** zero. The whole stack is open source (the orchestrator
  itself is MIT).

## 2) Problem and opportunity

Compliance and audit teams need, among other things:

1. **Customer due diligence (CDD)** on a risk-based approach, including
   enhanced due diligence when risk warrants it.
2. **Continuous monitoring**: a customer's risk profile is not a snapshot; it
   changes over time.
3. **Documented evidence**: records and supporting documentation that can be
   made available to the supervisor on request.

In practice, part of that information lives in open sources: the customer's
website, its subdomains, its IP addresses, its official social media
accounts, public mentions. Surveying them by hand is slow, inconsistent
between analysts and, above all, **hard to prove**: there is no systematic
record of what was checked, when, with what result, and under whose
authorisation.

The opportunity is to automate that survey while keeping control: every run
is recorded with its authorisation, its purpose, its outcome and the reviewer
responsible for the decision.

## 3) What the system is (in plain language)

| Concept | Meaning |
| --- | --- |
| **Target** | A digital asset authorised for monitoring (e.g. `empresa.com.uy`). Every target requires two mandatory fields: `authorization` (who approved it and when) and `purpose` (why it is monitored). |
| **Run** | One complete survey of a target. It ends in `success` (everything worked), `partial` (useful results with partial failures) or `failed` (no usable results). |
| **Observable** | A concrete datum found: a subdomain, an IP address, an e-mail, a social media account. |
| **Delta** | What is **new** since the previous run. The highest-value operational datum: what changed since we last looked. |
| **Finding** | Summary of the run's state and risk level (`low`, `medium`, `high`, `critical`, `unknown`), with justification and suggested next steps. |
| **Daily report** | Markdown (and PDF) document per target per day, with traceability, full inventory, delta, relationships and errors. |
| **Alert** | Automatic notification (signed webhook or e-mail) when new observables appear or risk exceeds the configured threshold. |

The system **only queries public sources** and **only against targets listed
and authorised** in a configuration file. It ships no intrusion, exploitation
or authentication capability against third-party systems. The authorised-use
policy is explicit and documented in the README and `SECURITY.md`.

## 4) Orchestration: how it works and why it matters

"Orchestrating" means coordinating several independent tools so they behave
as one reliable process. The flow of a run:

```text
 targets.yaml (authorised targets)
        │  schedule (cron) or manual trigger via API
        ▼
 ┌─────────────────────────────────────────────────┐
 │                ORCHESTRATOR                     │
 │                                                 │
 │ 1. COLLECT      OpenOSINT · SpiderFoot ·        │
 │                 SocialOSINT (opt-in)            │
 │        ▼                                        │
 │ 2. NORMALISE    everything to STIX 2.1          │
 │                 (international cyber-threat     │
 │                 intelligence standard)          │
 │        ▼                                        │
 │ 3. INGEST       into OpenCTI (single source of  │
 │                 truth) — with a durable retry   │
 │                 queue (outbox)                  │
 │        ▼                                        │
 │ 4. SYNTHESISE   AI-assisted (LLM) risk read,    │
 │                 always labelled as such         │
 │        ▼                                        │
 │ 5. REPORT       report.md + PDF + delta +       │
 │                 STIX bundle per run             │
 │        ▼                                        │
 │ 6. ALERT        signed webhook / e-mail, with   │
 │                 retry queue and DLQ             │
 └─────────────────────────────────────────────────┘
```

Why orchestration — rather than a loose tool — is the management-relevant
value:

- **Single source of truth.** All findings converge into OpenCTI with
  deterministic identifiers: the same datum observed twice is the same
  object, not a duplicate. No parallel spreadsheets.
- **Nothing is lost silently.** If OpenCTI is unavailable, the bundle of
  findings is parked in a **durable queue (outbox)** and retried
  automatically with growing backoff. If an alert cannot be delivered it goes
  through retries and, once exhausted, into a visible, manually replayable
  **dead-letter queue (DLQ)**. `partial` and `failed` states are recorded: a
  troubled run never looks successful.
- **Every end of the process is auditable.** Run id, UTC timestamps, the
  authorisation and purpose printed into the report, per-collector status,
  verbatim errors, and an HMAC-SHA256 signature on webhook alerts.
- **Bounded work by design.** Collectors carry hard budgets (max depth, max
  tool calls, timeouts). A scheduled run cannot expand uncontrollably against
  third-party infrastructure.
- **One operator is enough.** The whole process is automatic; the person
  reviews results and decides, instead of running tools.

## 5) Applicability to AML/CTF (Uruguayan framework)

> This section describes the **regulatory context** in which the tool may be
> useful. Interpreting regulation and applying it to a concrete case is the
> exclusive responsibility of the Compliance Officer and the firm's
> professionals.

Reference framework (verified as of September 2026):

- **Law No. 19,574** (2017-12-20), *Comprehensive Law against Money
  Laundering*, regulated by **Decree No. 379/018** and amended by **Law
  No. 20,469** (2026-03-19). It defines obliged parties (art. 13), the
  risk-based approach, and the due diligence, record-keeping and reporting
  obligations.
- **The national AML/CFT supervisor for non-financial obliged parties**
  oversees a sector that includes accountants, lawyers and notaries
  (Chapter V of Decree 379/018), and requires records and supporting
  documentation to be preserved and made available.
- **The national financial intelligence unit** receives suspicious
  transaction reports (STR).
- **Law No. 19,749** (2019): terrorist financing and targeted financial
  sanctions.
- **Law No. 20,075** (2022): sanction guidelines for non-financial obliged
  parties.

Official sources consulted on 2026-09-17:

- [Law No. 19,574, consolidated text (IMPO)](https://www.impo.com.uy/bases/leyes/19574-2017), especially arts. 13–16.
- [Decree No. 379/018, consolidated text (IMPO)](https://www.impo.com.uy/bases/decretos/379-2018), especially arts. 3–17.
- [Law No. 20,469 (IMPO)](https://www.impo.com.uy/bases/leyes/20469-2026), amending Law No. 19,574.
- The supervisory authority's current regulations, published on the official
  government portal.

Where the tool fits (and where it does not):

| Compliance process | Orchestrator contribution | Limit |
| --- | --- | --- |
| Customer due diligence / enhanced DD | Documented, reproducible survey of the customer/counterparty's digital footprint (domains, IPs, e-mails, official social accounts) as an **input** to the file | Does not identify beneficial owners; does not replace registry sources |
| Risk-based continuous monitoring | Scheduled runs (cron) with **delta**: what appeared or changed since the last review; threshold alerts | The AI-computed risk level is indicative and must be validated by the analyst |
| Evidence for audits and the supervisor | Dated reports with `run_id`, per-target authorisation and purpose; history kept under a configurable retention policy | **The 90-day default is operational, not regulatory.** For covered obliged parties, article 15 of Decree 379/018 sets a five-year minimum. Configure a compatible period or archive the evidence in controlled external storage, subject to professional review |
| Adverse media | AI-assisted analysis of associated social accounts (SocialOSINT), stored **labelled as unverified** | Not a list-screening service (PEP/sanctions); specialised providers exist for that |

**Rule of use:** the system produces inputs and process evidence. Compliance
decisions — risk classification, suspicious transaction reporting,
continuing a business relationship — are always human, reasoned and recorded
per internal procedures.

## 6) Internal control and auditability

From an internal-control standpoint, the system incorporates by design:

- **Documentation:** each run produces dated artifacts under
  `daily_reports/YYYY-MM-DD/<target>/` (report, STIX bundle, delta, optional
  PDF) plus a daily executive index. The filesystem alone provides neither
  immutability nor WORM storage.
- **Traceability:** correlation id per HTTP request, structured (JSON) logs
  with UTC timestamps, and run states persisted in a database.
- **Explicit authorisation:** no run without a target, no target without
  written `authorization` and `purpose`; both are printed into every report.
- **Segregation of duties:** whoever configures targets (with written
  authorisation) should not be the sole person reviewing runs or deciding on
  findings; role assignments remain an organisational control.
- **Chain of custody:** each run records its inputs, timestamps, collector
  outcomes and artifacts. Evidentiary preservation and approval records must
  follow the organisation's controlled procedure.
- **Access:** API protected by key (constant-time comparison, zero-downtime
  rotation) and, optionally, named operator logins via Keycloak (OIDC),
  which audit who logged in.
- **Retention:** configurable automatic purge of old runs and reports; the
  "already seen" memory is never purged, so the delta stays trustworthy.

## 7) Risks and limitations

| Risk | Built-in mitigation |
| --- | --- |
| Use against unauthorised targets | Mandatory `authorization`/`purpose` fields; authorised-use policy in README and SECURITY; no offensive capability in the codebase |
| AI "hallucinations" in the finding | The LLM synthesis is an indicative summary; observables are verifiable raw data; social media analysis is labelled *unverified*; risk levels always require human validation |
| Treating a partially failed run as valid | Explicit `partial`/`failed` states; operators must not base decisions on a `failed` run |
| Sensitive data leakage through alerts | Per-target `include_values: false` option (counts and types only); webhooks authenticated with HMAC-SHA256 |
| Reports altered after generation | Generated files are neither signed nor write-protected. For stronger evidentiary value, export them to versioned/WORM storage and record SHA-256 hashes under the internal policy |
| API exposure | Mandatory key in production (warns when empty), optional OIDC front door, health/metrics carry no target data |
| Privacy / platform terms | SocialOSINT uses official APIs, is opt-in per target, and warns about X/Twitter storage restrictions |
| Single-host dependency | Documented architectural decision (single instance, ADR-005); heavy state lives in OpenCTI; back up the SQLite volume + reports |

## 8) Operating cost and effort

- **Infrastructure:** one host (bare metal, VM or cloud) with ≥16 GB RAM
  (32 GB comfortable), ≥4 cores and ≥50 GB disk. Docker is the only software
  prerequisite.
- **Licences:** USD 0. The stack is 100 % open source (OpenCTI, optional
  MISP, SpiderFoot, Keycloak; the orchestrator is MIT).
- **Optional AI services:** with local Ollama, AI synthesis has no cost and
  sends no data off the server; cloud providers (Anthropic/OpenAI) incur
  per-use cost and transfer data to a third party (a decision to document).
- **Daily operation:** verify runs, prioritise high/critical risk, and record
  the resulting human decisions in the organisation's case-management flow.
- **Bootstrap:** `docker compose up -d`, copy two example configuration
  files, load authorised targets. Database schema maintenance is automatic
  on every startup.

## 9) Current status and phases

| Phase | Status | Contents |
| --- | --- | --- |
| 0 | ✅ | Architecture documented (ADRs), CI, Docker stack, health check |
| 1 | ✅ | OpenOSINT collector → STIX normalizer → OpenCTI ingest |
| 2 | ✅ | SpiderFoot collector, cron scheduling, daily reports |
| 3 | ✅ | Per-target LLM synthesis (Ollama / Anthropic / OpenAI) |
| 4a | ✅ | Webhook + e-mail alerts with retries and DLQ |
| 4b | ✅ | SocialOSINT (opt-in) + real MISP stack with official connector |
| 5 | ✅ | API auth, JSON logs, Prometheus metrics, Kubernetes chart, operator web console |
| — | ✅ | Optional OIDC front door (Keycloak + oauth2-proxy, ADR-006) |

The system is **functional end to end**: it collects, normalises, ingests,
synthesises, reports, alerts, and deploys both on Docker Compose and
Kubernetes. Its automated test suite and CI quality gates protect the core
contracts.

## 10) Annex: related documents

- [Project README (EN)](../../README.md) — installation and technical operation
- [Security policy](../../SECURITY.md) — authorised use and hardening
- Architecture decisions: [ADR-003 (OpenCTI as store)](../adr/ADR-003-opencti-as-store.md), [ADR-004 (language)](../adr/ADR-004-language-policy.md), [ADR-005 (auth & single instance)](../adr/ADR-005-api-auth-and-single-instance.md), [ADR-006 (OIDC front door)](../adr/ADR-006-oidc-proxy.md)

---

*Persisted technical identifiers (`success`, `partial`, `risk_level`) stay in
English by convention (ADR-004).*
