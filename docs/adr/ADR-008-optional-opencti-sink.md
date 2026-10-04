# ADR-008: Optional OpenCTI Sink via OPENCTI_ENABLED

**Date:** 2026-10-04  
**Status:** Accepted

## Context

ADR-003 established OpenCTI as the single source of truth and treated it as a
non-optional dependency. In practice, some deployments have no OpenCTI at all: a
lightweight or public demo install, or an operator who only wants reports,
findings, the delta and alerts. Collection, reporting and alerting must work
there without an OpenCTI instance.

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
- **It is not an outage switch.** While disabled, observables are recorded as
  seen without being ingested, so the delta treats them as known once the
  sink is turned back on: they are **never backfilled** into OpenCTI. A
  temporary OpenCTI outage or maintenance window is what the outbox
  (`opencti_outbox` table, `OPENCTI_OUTBOX_*` settings) already handles: failed bundles
  are queued and retried, and nothing is lost. Turning a deployment from
  `false` to `true` therefore starts the graph from that point on; re-ingesting
  earlier runs would need their `bundle.stix.json` files replayed by hand.
