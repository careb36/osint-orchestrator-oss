# STIX 2.1 conformance and best practices

[ADR-002](adr/ADR-002-stix-as-contract.md) makes STIX 2.1 the internal contract
and [ADR-003](adr/ADR-003-opencti-as-store.md) makes OpenCTI the store, so the
objects this service emits are read by tools it does not control. What matters
is therefore not only that a bundle validates against the specification, but
that other STIX consumers interpret it the same way.

The reference for that second question is the
[OASIS STIX 2.1 Best Practice Guide v1.0.0](https://www.cisa.gov/resources-tools/resources/oasis-stix-21-best-practice-guide)
(OASIS CTI Technical Committee, September 2022; CISA hosts the copy linked
here). It covers the non-`MUST` normative statements and the design choices the
specification deliberately leaves to producers. This page records, practice by
practice, what the orchestrator does and where to check it.

How to read the tables: **Met** means code enforces it and a test fails if it
regresses. **By design** means the guide recommends something this project
deliberately does differently, with the reason given. Nothing is listed as met
without a file to point at.

## Producing and identifying objects

| Practice | Status | Where |
| --- | --- | --- |
| §3.1 Version an object only via `id` + `modified`, with the creator as author | Met | `created` and `modified` on SDOs are pinned to the collection time (`_stix_timestamp`) instead of the `now()` that `stix2` defaults to, so re-normalising an unchanged `CollectorResult` emits identical objects and OpenCTI has nothing to update. The Identity objects carry a fixed `modified` that must be bumped by hand when their content changes |
| §3.1 Same `id` and `modified` but different content means a new object | Partial | Ids are derived from canonicalised content, so different observables never share an id. A Tavily Note whose qualification verdict changes across runs keeps its id and its collection time, so a consumer would hold the earlier labels. Left as is because the note text is the citation and re-qualifying the same page is rare; recorded rather than claimed as met |
| §3.2 Use an Identity instead of omitting `created_by_ref` | Met | `_IDENTITIES` in [`orchestrator/normalizer/stix.py`](../orchestrator/normalizer/stix.py): one Identity per collector |
| §3.3 Avoid dangling references | Met | SCOs, Relationships and Notes are emitted in the same bundle as the Identity they reference; `object_refs` never names an object held back |
| §3.4 A non-anonymised Identity should state contact information | Met | `_CONTACT_INFORMATION` on all five collector Identities |
| §4.3 Deterministic ids for SCOs from the identifier contributing properties | Met | SCOs get the spec-mandated uuid5 computed by the `stix2` library, so an observable produced here collides with the same one from MISP or an official OpenCTI connector |
| §4.3 Deterministic ids are not right for every SCO type | Met | Ids follow the specification's contributing properties per type; the phone customisation reads the value, never the observation context |
| §4.5 Exactly three sub-second digits on `created` and `modified` | Met | `_stix_timestamp` truncates microseconds to milliseconds; covered by `test_timestamps_carry_exactly_three_sub_second_digits` |
| §4.7 `spec_version` on SCOs | Met | Set to `2.1` on every SCO |
| §2.3 Avoid deprecated constructs (the 2.0 Cyber Observable Container) | Met | Only SCOs are emitted; nothing builds an observable container |

## Context on each object

| Practice | Status | Where |
| --- | --- | --- |
| §4.8 Use a confidence scale from Appendix A of the specification | Met | `confidence` is the 0–100 STIX value, plus `x_opencti_score` for OpenCTI's own ranking |
| §4.9 Every object should carry `confidence` | Met | Collectors without a measured score get their tool's documented baseline (`_TOOL_CONFIDENCE`); qualified evidence overrides it with the classifier's score |
| §4.9 Every object should carry `external_references` | Met where meaningful | A Tavily Note that cites a page now publishes it as an `external_reference` with the host as `source_name`, so the consumer renders a link. Relationships have no external source to cite |
| §4.1 Use consistent source names | Met | The URL host, so the same outlet always reports the same `source_name` |
| §4.6 Use `labels` only for what no other property expresses | By design | `labels` carries `target_fqdn`, the collector and the qualification (`category:`, `relevance:`). The alternative would be custom properties, which OpenCTI does not filter on |
| §5.8 `authors` on a Note names the application that wrote it | Met | `authors=[identity.name]`, because `created_by_ref` points at the collector's organisation-level Identity |
| §5.8 Notes are for non-creators to enrich someone else's object | By design | The orchestrator is the creator of its own observations and still emits Notes, because the qualification rationale has nowhere else to live: it is free text about how a page was judged, not a property of the observable. Confidence alone cannot carry it |

## Data handling

| Practice | Status | Where |
| --- | --- | --- |
| §3.5 Never share a TLP data marking | Met | No marking object is emitted; TLP is not represented at all |
| §2.2 Reuse common object repositories for shared objects | Not attempted | Locations and sectors are not emitted as Identity or Location objects with repository ids. Adding them means pinning a repository revision, which is a separate decision |
| §5.2 Reference the authoritative ATT&CK and CAPEC objects | Not applicable | OSINT collection here does not attribute techniques, so no `attack-pattern` is created |

## What the tests hold

`tests/unit/test_normalizer.py` and `tests/unit/test_normalizer_ids.py` carry
the guarantees above. The section *STIX 2.1 Best Practice Guide* in the former
asserts the author on a Note, contact information on every Identity, the
external reference on a cited source and the three-digit timestamp. A practice
that is listed here as met but loses its test should be treated as lost.

The conformance gap that remains is §2.2, and it is recorded rather than
hidden: an OpenCTI deployment that already holds the shared
[`cti-stix-common-objects`](https://github.com/oasis-open/cti-stix-common-objects)
content would de-duplicate better if targets resolved to those identities.
