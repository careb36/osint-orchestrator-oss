# ADR-003: OpenCTI as the Single Source of Truth

> 🇪🇸 [Español](ADR-003-opencti-as-store-es.md)

**Date:** 2026-09-04  
**Status:** Accepted

## Context

The orchestrator needs a graph store for OSINT findings, relationships, and threat intelligence. Options considered:

1. **Dedicated graph DB (Neo4j, ArangoDB):** full control, but duplicates the graph that OpenCTI already maintains internally via Elasticsearch + relationships.
2. **OpenCTI as the store:** use OpenCTI's existing graph, query it via GraphQL for synthesis.
3. **SQLite-only:** simple but no graph traversal, no built-in STIX import pipeline.

## Decision

**OpenCTI is the single source of truth for OSINT findings and their relationships.**

- The orchestrator never duplicates STIX objects in a second graph DB.
- All queries for synthesis (`synthesizer/`) hit OpenCTI's GraphQL API via `pycti`.
- The orchestrator's own SQLite (or Postgres in prod) stores **only operational state**: targets, run history, and SHA-256 hashes of observable IDs already ingested (for deduplication of new findings).
- MISP integration is handled by the official OpenCTI↔MISP connector (Docker profile), not by orchestrator code.

## Why not a dedicated graph DB

OpenCTI already ships with Elasticsearch (for full-text search), Redis (cache), RabbitMQ (message bus), and MinIO (file storage). Adding Neo4j would consume 2–4 GB additional RAM on a machine that already needs 12+ GB for the base stack. The value of a dedicated graph DB only materialises when the data model diverges from STIX — which is precisely what we want to avoid (see ADR-002).

## Consequences

- **Good:** no extra infrastructure cost.
- **Good:** OpenCTI's built-in deduplication handles duplicate STIX objects by ID.
- **Good:** free access to OpenCTI's visual graph explorer and dashboards.
- **Bad:** synthesis queries are limited to what OpenCTI exposes via GraphQL. Workaround: use raw GraphQL with `pycti`'s `CustomQuery` escape hatch.
- **Bad:** orchestrator cannot run without OpenCTI. Accepted — OpenCTI is a core dependency, not optional.
