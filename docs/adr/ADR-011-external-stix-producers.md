# ADR-011: External STIX 2.1 producers as an intake path

**Date:** 2026-10-15
**Status:** Accepted

## Context

ADR-002 makes STIX 2.1 the internal contract and `orchestrator/normalizer/stix.py`
the only *producer* of STIX objects in this repository: every collector returns a
`CollectorResult` and the normalizer builds the objects, so identity, confidence,
labels and ids follow one set of rules.

Some findings are already STIX 2.1 before they reach us. The
`investigation-assistant` engine (a separate repository) turns a case corpus
into a reviewed bundle: identities, `bank-account`/`text` observables,
`related-to` relationships and `note` evidence, with deterministic ids
(`uuid5(NAMESPACE_DNS, "osint-orchestrator." + seed)`) and TLP markings. Forcing
it through a `CollectorResult` would drop the evidence notes and re-classify
data a human already reviewed.

## Decision

Admit **external STIX 2.1 bundles** as an explicit **intake** path, without
relaxing ADR-002:

- `orchestrator/ingest_bundle.py` runs as
  `python -m orchestrator.ingest_bundle <file> [--work-name …] [--dry-run]`.
  It parses a bundle from disk and hands it to the existing `OpenCTISink`, which
  keeps ownership of retries and per-object rejection reporting.
- **Nothing in the intake builds or rewrites STIX.** It only parses and ingests;
  `normalizer/stix.py` remains the only producer.
- **`pycti` is imported before `stix2.parse`** because pycti registers the
  OpenCTI SCOs (`bank-account`, `text`, …) that the stix2 catalogue does not
  know. Without it, a bundle carrying them cannot even be parsed.
- Rejected objects are reported **by id and type** in the sink error, so the
  producer can be pointed at exactly what OpenCTI refused.
- The shared bundle contract is pinned as a **JSON Schema**
  (`orchestrator/contracts/stix-bundle.schema.json`, draft 2020-12,
  `x-contract-version: 1.0.0`): a copy of the producer's schema
  (`investigation-assistant`, its `IA-ADR-005`). A contract test validates
  intake fixtures against it, so a change to the engine's output is caught here
  before it reaches OpenCTI.
- The same intake is exposed over HTTP as `POST /bundles` (API-key protected,
  ADR-005): it validates the body against the pinned schema, parses with
  `pycti` imported first, and ingests via `OpenCTISink`. The engine
  (`investigation-assistant`) posts its bundle there after export.
- **A failed external ingest is not queued.** The OpenCTI outbox belongs to
  pipeline runs (its rows carry a `run_id` and a `target_id`), and an external
  bundle has neither. Once the sink's retries are spent, the failure goes back
  to the producer, which still holds the bundle: the CLI exits 1, and the
  endpoint answers 502 when the sink reports a failed ingest and 503 when
  OpenCTI could not be reached. Error details are localised (ADR-004); the
  raw error of an unreachable OpenCTI goes to the log only, since it can carry
  the platform's internal URL.

## Consequences

- A producer that already emits STIX can be ingested without being rewritten;
  the reviewer's classification and the evidence notes survive.
- The bundle must satisfy pycti's schemas: `bank-account` requires `iban` and
  `value`, and its id derives from `iban`; `text` requires `value`.
- Producers stay responsible for their own id determinism and mark handling; the
  sink only ingests.
- The schema copy must stay in sync with the producer: when the producer bumps
  its contract version, `orchestrator/contracts/SCHEMA_VERSION` and the copied
  schema are updated together (the contract test enforces the version match).
- The intake is available as a CLI (`python -m orchestrator.ingest_bundle`) and
  over HTTP (`POST /bundles`, API-key protected). A scheduled or streaming
  intake would be a separate decision, as would accepting bundles from
  untrusted producers.

## Alternatives

- **Convert external bundles into a `CollectorResult`:** rejected — it drops the
  evidence notes and re-classifies already-reviewed data.
- **Let producers write to OpenCTI directly:** rejected — it bypasses the
  retries and the rejection reporting the sink centralises.
- **Queue failed external bundles in the OpenCTI outbox:** deferred. It needs
  outbox rows without a run (a migration) and a decision on how long the
  orchestrator keeps a third party's bundle; until then the producer is the
  durable copy and retries on a 502, a 503 or exit code 1.
