# ADR-002: STIX 2.1 as the Internal Data Contract

**Date:** 2026-09-04  
**Status:** Accepted

## Context

The orchestrator ingests heterogeneous data from multiple OSINT tools (OpenOSINT JSON/GraphML, SpiderFoot JSON events, SocialOSINT reports). This data must be stored in OpenCTI, which natively speaks STIX 2.1. We need a single canonical format between collectors, the normalizer, and the sink.

## Decision

All inter-module data exchange uses **STIX 2.1 bundles** (via the `stix2` Python library) as the canonical format.

Rules:

1. A `CollectorResult` (Pydantic model) carries raw tool output. It does **not** leave the normalizer.
2. The normalizer converts every `CollectorResult` into a `stix2.Bundle` with:
   - `confidence` (0–100, based on tool reliability heuristic)
   - `x_opencti_score` (OpenCTI-specific, same range)
   - `created_by_ref` pointing to a per-tool `Identity` object
   - `labels` including the target name
3. The sink (`sinks/opencti.py`) accepts only `stix2.Bundle` objects. It never parses raw collector output.
4. No text strings or dicts cross module boundaries — only typed Pydantic models or `stix2` objects.

## Consequences

- **Good:** deduplication is trivial — STIX IDs are deterministic (`stix2.utils.new_version` or `ExternalReference` hashing). Running twice on the same data produces the same IDs.
- **Good:** future sinks (MISP, flat files) consume the same bundles without touching collectors.
- **Bad:** STIX vocabulary does not map 1:1 to every OSINT observable type. Unmapped types go in as `x-opencti-` custom objects.
- **Bad:** `stix2` library enforces strict spec validation; invalid data raises at normalizer time, which is the correct failure mode.
