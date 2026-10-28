# OSINT Orchestrator

> [Español](README.es.md)

Open-source due diligence for AML/CFT compliance teams and non-financial
obliged entities: it researches an entity in public sources, qualifies what it
finds with NVIDIA Nemotron on Nebius Token Factory, and leaves a signed,
auditable report.

## The problem

Open-source due diligence is done by hand: an analyst searches registries, news
and infrastructure data, copies results into a document and writes a
conclusion. It is slow, it does not scale to periodic re-checks, and it leaves
no trail showing which sources were consulted, what they said that day, or
whether the file was edited afterwards.

## How it works

```mermaid
flowchart LR
    T[Target<br/>cron or API] --> C[Collectors<br/>Tavily · SpiderFoot · OpenOSINT · Amass]
    C --> Q[Evidence qualification<br/>Nemotron fast]
    Q --> N[STIX 2.1]
    N --> O[(OpenCTI)]
    N --> S[Synthesis<br/>Nemotron reasoning]
    S --> R[Report + signed manifest]
    R --> A[Alerts]
```

- **Collect.** Each authorised target is researched on a schedule or on demand
  by web search (Tavily) and infrastructure collectors.
- **Qualify.** Every web result is classified against the entity: category
  (sanctions, litigation, adverse media…), relevance, confidence and a one-line
  rationale.
- **Normalise.** Findings become STIX 2.1 with deterministic ids and can be
  ingested into OpenCTI.
- **Synthesise.** A risk level with its justification, citing the evidence it
  relies on, plus what is new since the previous run.
- **Seal.** Each run's files are hashed into an HMAC-signed manifest chained to
  the previous run, so any later edit or removal is detectable.

Details: [architecture](docs/architecture.md).

## NVIDIA Nemotron on Nebius Token Factory

A target opts into the Token Factory OpenAI-compatible endpoint with
`llm: nebius` in `targets.yaml` (or with `llm: openai` when
`LLM_PROVIDER=nebius`). Targets default to `llm: local`, which sends the LLM
prompts to the Ollama server at `LLM_BASE_URL` and never to a cloud LLM
provider; the prompts stay on your infrastructure only if that server does.
Two model routes are configured independently:

| Route | Setting | Model used in our runs | Job | Code |
| --- | --- | --- | --- | --- |
| fast | `LLM_MODEL_FAST` | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | Qualify each web result against the entity | [`synthesizer/qualify.py`](orchestrator/synthesizer/qualify.py) |
| reasoning | `LLM_MODEL_REASONING` | `nvidia/nemotron-3-super-120b-a12b` | Risk synthesis for the run | [`synthesizer/__init__.py`](orchestrator/synthesizer/__init__.py) |

Both calls request a JSON-schema response, are retried within a time budget, and
every returned value is validated before it is stored. The startup check that
the configured models are served follows the global setting, not the target's
`llm`: it runs only with `LLM_PROVIDER=nebius` or `openai` and that provider's
key set, so a deployment that opts in with `llm: nebius` alone gets no startup
check.
Requests, tokens and model availability are exported as Prometheus metrics.
Provider client:
[`providers/openai_compat.py`](orchestrator/synthesizer/providers/openai_compat.py).

### Run it on Token Factory

Four lines in `.env`, and `llm: nebius` on each target in `targets.yaml`:

```bash
LLM_PROVIDER=nebius
NEBIUS_API_KEY=<your Token Factory key>
LLM_MODEL_FAST=nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B
LLM_MODEL_REASONING=nvidia/nemotron-3-super-120b-a12b
```

`LLM_PROVIDER=nebius` also turns on the startup check that both models are
served and sends `llm: openai` targets to Token Factory. Without the two
`LLM_MODEL_*` lines both routes fall back to `LLM_MODEL`, whose default,
`llama3.2`, names an Ollama model, not a Token Factory one.

## Tavily

The Tavily collector ([`collectors/tavily.py`](orchestrator/collectors/tavily.py))
calls the search API at run time with five due-diligence queries per search
term: adverse media and sanctions, ownership, legal proceedings, criminal
record and administrative sanctions, with no time filter. Terms are
the entity names configured for the target (the domain by default), quoted and
searched across third-party sources. Each distinct page becomes a STIX `url`
observable and a Note, is qualified by Nemotron, and is recorded in
`qualified_evidence.json` under the run's signed manifest.

## Quickstart

Three ways in, from no keys to the full stack. Each needs Docker with Compose
v2.20+ and starts the same way:

```bash
cp .env.example .env                    # passwords, tokens and API keys it lists
cp targets.example.yaml targets.yaml    # only targets you are authorised to assess
docker compose up -d --build            # SpiderFoot and the orchestrator (OPENCTI_ENABLED=false)
```

Then see [operations](docs/operations.md), [configuration](docs/configuration.md)
and, for a server, [deploy](docs/deploy.md).

### 1. See it first: the showcase run (no API keys)

Before configuring a collector or a model provider, replay the recorded sample
through the real pipeline and open the console with two finished runs in it:

```bash
docker compose exec orchestrator python -m orchestrator.showcase
# then http://localhost:8000/console
```

The container writes reports to `./daily_reports` as uid 1000; the directory
ships in the clone so Docker does not create it root-owned. On Linux, if your
user is not uid 1000, run `sudo chown -R 1000:1000 daily_reports` first
([deploy](docs/deploy.md)).

The showcase replays [`orchestrator/showcase_data/`](orchestrator/showcase_data/): a fictitious entity
(reserved `.example` names, TEST-NET addresses) assessed twice, the second run
adding a sanctions-list entry and an ownership investigation. Only the
collector output and the model's answers are recorded; normalisation to STIX,
the delta against the first run, the report, `qualified_evidence.json`, the
signed and chained manifest and the alert case are produced on your machine
by the same code a scheduled run uses. The rows say provider `showcase` and
model `recorded-sample`, so the console never credits a model that did not
run. The target `showcase-example` ships `enabled: false`: the scheduler never
runs it and it costs no API call. Details in
[operations](docs/operations.md#showcase-run).

### 2. A real run with two keys (Token Factory and Tavily)

The shortest live path is Tavily → Nemotron: web evidence collected at run
time, qualified on the fast route and synthesised on the reasoning route, with
no SpiderFoot scan and no OpenCTI. In `.env`, the four Token Factory lines from
[Run it on Token Factory](#run-it-on-token-factory) plus the search key:

```bash
NEBIUS_API_KEY=<your Token Factory key>
TAVILY_API_KEY=<your Tavily key>
```

In `targets.yaml`, copy the `showcase-example` block under a **new `id`**
(the sample's runs, seen observables and risk history stay with the sample;
a real entity must not inherit them), set `enabled: true`, and replace
`fqdn` and `search_terms` with an entity you are authorised to assess; keep
`openosint` and `spiderfoot` disabled as the block ships them, and leave the
sample block as it is. Restart the orchestrator so it reads the keys
(`docker compose up -d orchestrator`; `targets.yaml` is read on every
request) and start the run from the console's *Start run* button or
`POST /targets/<id>/run`. A run takes about a minute; the console shows
which model qualified each piece of evidence and which one wrote the finding.

### 3. The full stack

OpenCTI as the knowledge graph, SpiderFoot and OpenOSINT as collectors,
scheduled runs and alerts: 16 GB of RAM, `OPENCTI_ENABLED=true` in `.env` and
the profile on the command line:

```bash
docker compose --profile opencti up -d --build
```

Existing sink-on installs must add `--profile opencti` or set
`COMPOSE_PROFILES=opencti` in `.env`.

**Operator dashboard:** <http://localhost:8000/console>, in Spanish or English.
Key figures, targets ordered by what needs attention, active runs, findings,
evidence with search and filters, and a Start-run action; it asks for
`ORCHESTRATOR_API_KEY` on first load. Source in [`ui/`](ui/README.md); the
images build it, so nothing else is needed.

Both screenshots are the console after the showcase run of tier 1: the
fictitious sample, two runs, no API key.

![Overview: key figures and targets ordered by attention, the showcase target last because it is disabled](docs/img/dashboard-overview-en.png)

![Run workspace: each piece of evidence with its category, relevance, confidence and rationale, qualified by the recorded sample](docs/img/dashboard-run-evidence-en.png)

## Built during the hackathon

This project was built during a hackathon. The commit `Baseline: pre-hackathon
snapshot` marks what existed before the event: the collection pipeline, STIX
normalisation, OpenCTI ingest, reports, alerts and the API. The full history of
features added since then, with their pull requests, is kept in
[docs/HACKATHON.md](docs/HACKATHON.md).

## Responsible use

The orchestrator runs reconnaissance against whatever is listed in
`targets.yaml`, and some collectors make live requests to the target. Add only
targets you own or are authorised in writing to assess; `authorization` and
`purpose` are mandatory per target and written into every report. Model output
is an aid for an analyst, not a determination. See [SECURITY](SECURITY.md).

## Roadmap

| Item | Status |
| --- | --- |
| Evidence qualification and evidence chain | Done |
| Operator dashboard (overview, triage, investigation) | Done |
| Qualification of relationships between entities | Planned |
| Data-quality indicators per source | Planned |
| Document NLP (filings, court records) | Planned |
| Authoritative sources (registries, sanctions lists) | Planned |

## Documentation

[Architecture](docs/architecture.md) · [Configuration](docs/configuration.md) ·
[Operations](docs/operations.md) · [Deploy](docs/deploy.md) · [Decisions](docs/adr/) ·
[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) ·
[Changelog](CHANGELOG.md) · [Hackathon history](docs/HACKATHON.md)

MIT licence — see [LICENSE](LICENSE).
