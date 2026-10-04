# ADR-001: Modular Monolith Architecture

**Date:** 2026-09-04  
**Status:** Accepted

## Context

The orchestrator needs to coordinate multiple OSINT collectors (OpenOSINT, SpiderFoot, SocialOSINT), a normalizer, a sink to OpenCTI, a synthesizer, and a report generator. We must choose between microservices, a modular monolith, or a monolith.

The project starts with a single developer and zero operational users. Splitting into microservices at day zero adds network latency, distributed tracing overhead, independent deployment pipelines, and inter-service auth — all cost without benefit when there is no scaling pressure yet.

## Decision

Deploy the orchestrator as a **single Python process** (`orchestrator/`) with well-defined internal module boundaries:

- `collectors/` — one file per tool, each implementing `BaseCollector`
- `normalizer/` — pure functions, STIX 2.1 output only
- `sinks/` — one file per destination (OpenCTI today, others later)
- `synthesizer/` — LLM integration, isolated behind an interface
- `reports/` — artifact generation, no side effects on the data model

Modules communicate only through typed Pydantic models (`CollectorResult`, `Finding`). No shared mutable state, no cross-module imports outside the orchestrator's `main` pipeline.

## Splitting Criteria (when to extract a service)

Extract a module into a separate service **only** when one of the following is true:

1. A module needs to scale independently (e.g., SpiderFoot scans are CPU-bound and block report generation).
2. A module needs a different language/runtime.
3. A module is consumed by a second application.

Until then, the monolith boundary is the unit of deployment.

## Consequences

- **Good:** single `docker compose up`, one log stream, simple debugging, no inter-service auth.
- **Good:** easy refactor — module boundaries are enforced by code review, not network topology.
- **Bad:** a crash in the collector loop crashes the scheduler too. Mitigated by catching exceptions per collector and continuing.
- **Bad:** cannot scale collectors independently. Accepted for v1.
