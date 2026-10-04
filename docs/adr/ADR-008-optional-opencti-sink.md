# ADR-008: Optional OpenCTI Sink via OPENCTI_ENABLED

> 🇪🇸 [Español](ADR-008-optional-opencti-sink-es.md)

**Date:** 2026-10-04  
**Status:** Accepted

## Context

ADR-003 established OpenCTI as the single source of truth and treated it as a
non-optional dependency. In practice, operators also need a lightweight mode
for demos, maintenance windows, or temporary OpenCTI outages where collection,
reporting, and alerting can continue without ingesting into OpenCTI.

## Decision

Introduce `OPENCTI_ENABLED` (default `true`) as a runtime switch:

- `true`: current behaviour (ingest to OpenCTI and run the outbox retry worker).
- `false`: skip OpenCTI ingest and skip outbox replay/worker registration.

When disabled, pipeline runs still produce reports/findings/delta/alerts and
must not be marked partial only because OpenCTI ingest is skipped.

## Consequences

- ADR-003 remains the default architecture for production (`OPENCTI_ENABLED=true`).
- With `OPENCTI_ENABLED=false`, OpenCTI is no longer the active sink for that
  deployment, so the OpenCTI knowledge graph (and flows that depend on it, such
  as connector-driven exchanges) is intentionally unavailable.
- This mode is operationally useful but should be treated as a degraded
  knowledge-graph posture, not as a replacement for ADR-003.
