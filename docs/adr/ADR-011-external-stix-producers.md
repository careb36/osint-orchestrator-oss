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
  keeps ownership of retries, per-object rejection reporting and the outbox.
- **Nothing in the intake builds or rewrites STIX.** It only parses and ingests;
  `normalizer/stix.py` remains the only producer.
- **`pycti` is imported before `stix2.parse`** because pycti registers the
  OpenCTI SCOs (`bank-account`, `text`, …) that the stix2 catalogue does not
  know. Without it, a bundle carrying them cannot even be parsed.
- Rejected objects are reported **by id and type** in the sink error, so the
  producer can be pointed at exactly what OpenCTI refused.

## Consequences

- A producer that already emits STIX can be ingested without being rewritten;
  the reviewer's classification and the evidence notes survive.
- The bundle must satisfy pycti's schemas: `bank-account` requires `iban` and
  `value`, and its id derives from `iban`; `text` requires `value`.
- Producers stay responsible for their own id determinism and mark handling; the
  sink only ingests.
- The intake is CLI-only for now. A scheduled or streaming intake would be a
  separate decision, as would accepting bundles from untrusted producers.

## Alternatives

- **Convert external bundles into a `CollectorResult`:** rejected — it drops the
  evidence notes and re-classifies already-reviewed data.
- **Let producers write to OpenCTI directly:** rejected — it bypasses the
  retries, rejection reporting and the outbox the sink centralises.
