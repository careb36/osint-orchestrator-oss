# ADR-007: Signed Per-Run Evidence Manifests Chained per Target

**Status:** Accepted (2026-09-27)  
**Date:** 2026-09-23  
**Deciders:** careb36

---

## Context

Every pipeline run writes its artefacts under
`daily_reports/<YYYY-MM-DD>/<target_id>/`: `report.md`, `bundle.stix.json`,
`delta.json` and, when a PDF backend is available, `report.pdf`
(`orchestrator/reports/__init__.py`). The `runs` table records when the run
happened, which collectors ran, how many observables were new and where the
report lives. Nothing today proves that the files on disk are the ones the run
produced, or that no report in a target's history was altered or removed
afterwards. For the audiences this project targets (compliance, AML, forensic
readiness — see `docs/business/`) that gap is the difference between "a report"
and "evidence".

`ORCHESTRATOR_SECRET_KEY` exists in `orchestrator/config.py` (default
`insecure-dev-key`) and is read by nothing. The roadmap has carried a
"Phase 6 — evidence chain" line since ADR-005 without a design.

## Decision

### 1. A manifest per run

After the artefacts of a run are written, the pipeline writes
`manifest.json` in the same directory:

```json
{
  "manifest_version": 1,
  "run_id": 42,
  "target_id": "example",
  "started_at": "2026-09-23T08:00:00+00:00",
  "finished_at": "2026-09-23T08:07:12+00:00",
  "status": "success",
  "collectors_run": ["openosint", "spiderfoot"],
  "artefacts": {
    "report.md": "sha256:…",
    "bundle.stix.json": "sha256:…",
    "delta.json": "sha256:…",
    "report.pdf": "sha256:…"
  },
  "previous_manifest_sha256": "sha256:…",
  "signature": "hmac-sha256:…"
}
```

- `artefacts` lists every file the run produced with its SHA-256. The example
  shows a run that produced a PDF; when no PDF backend is available the
  `report.pdf` key is **absent**, never `null`. Files are hashed after they are fully
  written, from disk, never from in-memory content.
- `previous_manifest_sha256` is the SHA-256 of the manifest of the **previous
  terminal run of the same target** (`runs.manifest_sha256`, see §3), or
  `null` for the first run. This is what turns independent manifests into a
  chain: removing or altering any earlier manifest breaks every later link.
- `signature` is HMAC-SHA256 over the canonical JSON of every field except
  `signature` (keys sorted, no whitespace, UTF-8), keyed with
  `ORCHESTRATOR_SECRET_KEY`. The manifest's own SHA-256 (what the next run
  chains to and what the database stores) is computed over the final file,
  signature included.

**Versioning.** `manifest_version` changes only when a verifier written for
the previous version could no longer check a new manifest: a different
canonicalisation, hash or signature algorithm, or a change in the meaning of
an existing field. Adding a field does not bump it, because the signature
covers every field present and a verifier canonicalises whatever it reads.
Verifiers dispatch on `manifest_version`, keep every version they ever
shipped, and report an unknown version as `unsupported_version`, never as
tampering. Manifests are never migrated in place.

### 2. Signing key

`ORCHESTRATOR_SECRET_KEY` becomes the signing key. It keeps its current name
and default so `.env.example` and the README configuration tables do not
change; with the default value the orchestrator still signs, and logs one
WARNING at startup (`extra={"setting": "ORCHESTRATOR_SECRET_KEY"}`), exactly
as an empty `ORCHESTRATOR_API_KEY` is handled today.

Rotating the key does not invalidate the chain of hashes, but after a rotation
**every** manifest signed before it reports `signature_key` until the verifier
is given the old key. That is expected, not noise to suppress: manifests are
never re-signed, because re-signing would rewrite evidence after the fact and
an auditor could no longer tell which key vouched for a run at the time. The
rotation procedure is therefore: keep the retired key offline, record the
rotation date, and verify older runs against the retired key offline (the
manifest format is self-contained for that). A built-in multi-key verifier is
out of scope for this ADR.

### 3. Persistence

Alembic migration `0005` adds `manifest_sha256: str | None` to `runs`
(nullable, indexed). The column lets the API verify the chain of a target
without trusting the file system for the link values.

The manifest is the **last** file a run writes, and `manifest_sha256` is set in
the same transaction that records the run's final status. A run whose
`manifest_sha256` is `NULL` is *unsealed*: it failed before any artefact was
written, or after writing some artefacts but before the manifest. Unsealed runs
are not links: the next sealed run chains to the last sealed run before it,
and their partial directories are left on disk for diagnosis and removed by
retention like any other. Verification never treats an unsealed run as
tampering; it counts them separately (`unsealed` in §4).

### 4. API (protected router)

- `GET /runs/{run_id}/manifest` returns the stored manifest as JSON, 404
  (`i18n` key `manifest.not_found`) when the run has none.
- `GET /targets/{target_id}/chain/verify` walks the target's terminal runs in
  `started_at` order and, for each, re-hashes the artefacts on disk, checks the
  signature with the current key and checks `previous_manifest_sha256` against
  the stored hash of the preceding run. Response:

  ```json
  {"ok": false, "checked": 12, "unsealed": 1, "first_broken_run_id": 37,
   "reason": "artefact_hash", "detail": "report.md"}
  ```

  `checked` counts sealed runs, `unsealed` the runs skipped under §3.
  `reason` ∈ `artefact_hash | artefact_missing | manifest_missing |
  signature | signature_key | chain_link | unsupported_version`. Verification
  stops at the first broken link. The text a human sees comes from `orchestrator/i18n.py`
  (`chain.reason.*`, `es` + `en`).

### 5. Observability

Metric `osint_orchestrator_evidence_chain_verify_total{target_id, outcome}`
(`outcome` ∈ `ok | broken | error`) in `orchestrator/metrics.py`, with its
row in both README metric tables. The run log line that already reports the
report path gains `manifest_sha256` in `extra`.

### 6. What this ADR does not do

- It does not time-stamp against an external authority or anchor hashes in a
  ledger. The chain proves internal consistency and detects post-hoc edits;
  it does not prove *when* a manifest was written to a third party. A later
  ADR may add RFC 3161 time stamps on top of the same manifest.
- It does not encrypt artefacts or restrict who can read them; ADR-005 and
  ADR-006 cover access.
- It does not sign the STIX bundle inside OpenCTI; OpenCTI remains the source
  of truth for *observables* (ADR-003), the file system remains the source of
  truth for *reports*, and the manifest binds the two through the bundle hash.

## Consequences

- One new file per run directory; retention (`orchestrator/retention.py`)
  removes it with the directory, and the verification endpoint reports the
  runs it can no longer check as `manifest_missing` rather than as tampering
  when their `runs` row is gone too.
- The pipeline gains one synchronous step after report generation (hashing a
  few files); no new dependency (`hashlib`, `hmac`, `json` from the standard
  library).
- Operators get a single call to answer "has anything in this target's
  history been altered?", and auditors get a per-run manifest they can verify
  offline with the key and `sha256sum`.
- Tests required by the implementation issue: deterministic manifest for fixed
  inputs; changing one byte of `report.md` breaks verification at that run
  with `artefact_hash`; verifying with a different key reports
  `signature_key`; a run that fails after writing `report.md` but before the
  manifest is counted in `unsealed` and the next run chains past it; a
  manifest with `manifest_version: 99` reports `unsupported_version`; a target
  with no runs verifies `ok` with `checked: 0`;
  `alembic check` clean after migration `0005`.

## Links

- [ADR-003: OpenCTI as the single source of truth](ADR-003-opencti-as-store.md)
- [ADR-005: Static API keys, structured observability and a single-instance deployment](ADR-005-api-auth-and-single-instance.md)
- [ADR-006: Optional OIDC proxy as a perimeter layer](ADR-006-oidc-proxy.md)
- `orchestrator/reports/__init__.py` — artefact paths
- `orchestrator/config.py` — `ORCHESTRATOR_SECRET_KEY`
