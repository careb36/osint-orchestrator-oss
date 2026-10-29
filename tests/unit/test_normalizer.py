"""Unit tests for orchestrator.normalizer.stix"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

import pytest

from orchestrator.models import (
    CollectorName,
    CollectorResult,
    Observable,
    Relationship,
)
from orchestrator.normalizer.stix import _IDENTITIES, normalize

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_result(**kwargs) -> CollectorResult:
    defaults = dict(
        collector=CollectorName.OPENOSINT,
        target_fqdn="example.com",
        collected_at=datetime(2026, 9, 4, tzinfo=UTC),
        success=True,
    )
    defaults.update(kwargs)
    return CollectorResult(**defaults)


# ── Tests: bundle structure ───────────────────────────────────────────────────


def test_bundle_has_identity():
    result = _make_result(observables=[])
    bundle = normalize(result)
    identity_id = _IDENTITIES[CollectorName.OPENOSINT].id
    ids = [o["id"] for o in bundle.get("objects", [])]
    assert identity_id in ids


def test_bundle_is_valid_stix():
    result = _make_result(observables=[Observable(type="domain-name", value="example.com")])
    bundle = normalize(result)
    # stix2 library validates on construction; if no exception → valid
    assert bundle.type == "bundle"


def test_bundle_json_round_trips():
    result = _make_result(observables=[Observable(type="ipv4-addr", value="1.2.3.4")])
    bundle = normalize(result)
    raw = bundle.serialize()
    parsed = json.loads(raw)
    assert parsed["type"] == "bundle"
    assert len(parsed["objects"]) >= 2  # identity + observable


# ── Tests: observable mapping ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "obs_type,value,expected_stix_type",
    [
        ("domain-name", "sub.example.com", "domain-name"),
        ("ipv4-addr", "192.168.1.1", "ipv4-addr"),
        ("ipv6-addr", "::1", "ipv6-addr"),
        ("url", "https://example.com/path", "url"),
        ("email-addr", "user@example.com", "email-addr"),
    ],
)
def test_observable_types(obs_type: str, value: str, expected_stix_type: str):
    result = _make_result(observables=[Observable(type=obs_type, value=value)])
    bundle = normalize(result)
    types = [o["type"] for o in bundle.get("objects", [])]
    assert expected_stix_type in types


def test_unknown_observable_becomes_indicator():
    result = _make_result(observables=[Observable(type="x-custom-thing", value="something")])
    bundle = normalize(result)
    types = [o["type"] for o in bundle.get("objects", [])]
    assert "indicator" in types


# ── Tests: relationships ──────────────────────────────────────────────────────


def test_relationship_created():
    rel = Relationship(
        source_value="example.com",
        source_type="domain-name",
        target_value="1.2.3.4",
        target_type="ipv4-addr",
        relationship_type="resolves-to",
    )
    result = _make_result(
        observables=[
            Observable(type="domain-name", value="example.com"),
            Observable(type="ipv4-addr", value="1.2.3.4"),
        ],
        relationships=[rel],
    )
    bundle = normalize(result)
    rels = [o for o in bundle.get("objects", []) if o["type"] == "relationship"]
    assert len(rels) == 1
    assert rels[0]["relationship_type"] == "resolves-to"


def test_relationship_missing_observable_skipped():
    """If one side of a relationship isn't in the observables, skip it silently."""
    rel = Relationship(
        source_value="example.com",
        source_type="domain-name",
        target_value="MISSING",
        target_type="ipv4-addr",
        relationship_type="resolves-to",
    )
    result = _make_result(
        observables=[Observable(type="domain-name", value="example.com")],
        relationships=[rel],
    )
    bundle = normalize(result)
    rels = [o for o in bundle.get("objects", []) if o["type"] == "relationship"]
    assert len(rels) == 0


# ── Tests: notes ──────────────────────────────────────────────────────────────


def test_notes_become_stix_notes():
    result = _make_result(
        observables=[],
        notes=["This is a test note with enough characters to be a note."],
    )
    bundle = normalize(result)
    notes = [o for o in bundle.get("objects", []) if o["type"] == "note"]
    assert len(notes) == 1
    assert "test note" in notes[0]["content"]


def test_same_note_text_gets_a_different_id_per_target():
    """The identity is per collector, so without the target in the id two
    targets' "no results" notes would merge into one object in OpenCTI."""
    note = "tavily: no public results matched the query set"
    ids = {
        next(
            o["id"]
            for o in normalize(_make_result(target_fqdn=fqdn, notes=[note])).get("objects", [])
            if o.get("type") == "note"
        )
        for fqdn in ("a.example", "b.example")
    }
    assert len(ids) == 2


def test_empty_notes_skipped():
    result = _make_result(observables=[], notes=["", "   ", ""])
    bundle = normalize(result)
    notes = [o for o in bundle.get("objects", []) if o["type"] == "note"]
    assert len(notes) == 0


# ── Tests: STIX 2.1 Best Practice Guide (OASIS v1.0.0) ───────────────────────


def test_notes_name_their_author():
    """BP 5.8: created_by_ref identifies the organisation, so the application
    that wrote the note belongs in authors."""
    result = _make_result(observables=[], notes=["A note long enough to be stored."])
    note = next(o for o in normalize(result).get("objects", []) if o["type"] == "note")
    assert note["authors"] == ["OpenOSINT"]


def test_identity_modified_never_precedes_created():
    """BP 3.1: a consumer only takes a new version when `modified` moves
    forward, so an identity edit must bump it."""
    for identity in _IDENTITIES.values():
        assert identity.modified >= identity.created, identity.name


def test_identity_states_how_to_contact_the_producer():
    """BP 3.4: a non-anonymised Identity should carry contact information, so a
    consumer holding a dangling reference knows who to ask."""
    for identity in _IDENTITIES.values():
        assert identity.get("contact_information")


def test_tavily_note_cites_its_source_as_an_external_reference():
    """BP 4.1 / Table 1: the cited page belongs in external_references, where a
    consumer renders it as a link, not only inside the note text."""
    result = _make_result(
        collector=CollectorName.TAVILY,
        observables=[],
        notes=["Found a page | url=https://news.example/article-1 | title=Report"],
    )
    note = next(o for o in normalize(result).get("objects", []) if o["type"] == "note")
    assert note["external_references"] == [
        {"source_name": "news.example", "url": "https://news.example/article-1"}
    ]


def test_note_without_a_cited_url_has_no_external_references():
    result = _make_result(collector=CollectorName.TAVILY, observables=[], notes=["no urls here"])
    note = next(o for o in normalize(result).get("objects", []) if o["type"] == "note")
    assert "external_references" not in note


def test_timestamps_carry_exactly_three_sub_second_digits():
    """BP 4.5: modified decides which version is current, so the sub-second
    digits should be exactly three."""
    # Serialised, because that is the JSON a consumer receives.
    data = json.loads(normalize(_make_result(observables=[])).serialize())
    stamps = {o[k] for o in data["objects"] for k in ("created", "modified") if k in o}
    assert stamps
    for stamp in stamps:
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", stamp), stamp


def test_renormalising_the_same_result_emits_identical_objects():
    """stix2 defaults created/modified to now(), which would hand OpenCTI a new
    version of every Note on every run. Pinning them to the collection time makes
    a re-run a true no-op. The bundle id is excluded: the specification wants a
    fresh one per transmission and consumers do not store it."""
    when = datetime(2026, 10, 29, 12, 0, 0, 123456, tzinfo=UTC)
    result = _make_result(
        collector=CollectorName.TAVILY,
        observables=[Observable(type="url", value="https://news.example/a")],
        notes=["Found a page | url=https://news.example/a"],
        collected_at=when,
    )
    first = json.loads(normalize(result).serialize())["objects"]
    second = json.loads(normalize(result).serialize())["objects"]
    assert first == second


def test_millisecond_truncation_does_not_change_the_id():
    """Truncating to milliseconds must not fork the identity of an object."""
    notes = ["Scheduled collection completed without new observables."]
    ids = set()
    for micro in (123456, 789000):
        result = _make_result(
            observables=[],
            notes=notes,
            collected_at=datetime(2026, 10, 29, 12, 0, 0, micro, tzinfo=UTC),
        )
        ids.add(
            next(
                o["id"]
                for o in json.loads(normalize(result).serialize())["objects"]
                if o["type"] == "note"
            )
        )
    assert len(ids) == 1


# ── Tests: deduplication properties ──────────────────────────────────────────


def test_same_result_same_bundle_ids():
    """Normalizing the same result twice must produce the same STIX IDs (idempotent)."""
    result = _make_result(
        observables=[
            Observable(type="domain-name", value="example.com"),
            Observable(type="ipv4-addr", value="1.2.3.4"),
        ]
    )
    bundle1 = normalize(result)
    bundle2 = normalize(result)
    ids1 = {o["id"] for o in bundle1.get("objects", [])}
    ids2 = {o["id"] for o in bundle2.get("objects", [])}
    assert ids1 == ids2


# ── Tests: per-collector identity ─────────────────────────────────────────────


def test_spiderfoot_uses_spiderfoot_identity():
    result = _make_result(
        collector=CollectorName.SPIDERFOOT,
        observables=[Observable(type="domain-name", value="example.com")],
    )
    bundle = normalize(result)
    sf_id = _IDENTITIES[CollectorName.SPIDERFOOT].id
    ids = [o["id"] for o in bundle.get("objects", [])]
    assert sf_id in ids


def test_openosint_and_spiderfoot_have_different_identities():
    assert _IDENTITIES[CollectorName.OPENOSINT].id != _IDENTITIES[CollectorName.SPIDERFOOT].id


# ── Tests: labels ─────────────────────────────────────────────────────────────


def test_labels_include_target_fqdn():
    result = _make_result(observables=[Observable(type="domain-name", value="example.com")])
    bundle = normalize(result)
    domain_obj = next(o for o in bundle.get("objects", []) if o.get("type") == "domain-name")
    # SCOs store labels in custom property x_labels (not top-level labels).
    # Check for exact membership in the list, not substring match.
    x_labels: list = domain_obj.get("x_labels", [])
    assert result.target_fqdn in x_labels


def test_labels_include_collector_name():
    result = _make_result(
        collector=CollectorName.SPIDERFOOT,
        observables=[Observable(type="domain-name", value="example.com")],
    )
    bundle = normalize(result)
    domain_obj = next(o for o in bundle.get("objects", []) if o.get("type") == "domain-name")
    assert "spiderfoot" in domain_obj.get("x_labels", [])


# ── Tests: autonomous-system ──────────────────────────────────────────────────


def test_autonomous_system_numeric():
    result = _make_result(observables=[Observable(type="autonomous-system", value="AS64496")])
    bundle = normalize(result)
    ases = [o for o in bundle.get("objects", []) if o.get("type") == "autonomous-system"]
    assert len(ases) == 1
    assert ases[0]["number"] == 64496


@pytest.mark.parametrize("value", ["as64496", "ASN 64496", "64496", " AS64496 "])
def test_autonomous_system_accepts_the_usual_spellings(value: str):
    result = _make_result(observables=[Observable(type="autonomous-system", value=value)])
    bundle = normalize(result)
    ases = [o for o in bundle.get("objects", []) if o.get("type") == "autonomous-system"]
    assert [o["number"] for o in ases] == [64496]


@pytest.mark.parametrize("value", ["not-a-number", "AS-foo", "ASN", "AS15169 Google LLC"])
def test_autonomous_system_without_a_number_is_dropped_not_as0(value: str):
    """Every unparseable value used to become AS0, so unrelated ASNs shared one id."""
    result = _make_result(observables=[Observable(type="autonomous-system", value=value)])
    bundle = normalize(result)
    assert [o for o in bundle.get("objects", []) if o.get("type") == "autonomous-system"] == []


# ── Tests: empty result ───────────────────────────────────────────────────────


def test_empty_observables_returns_bundle_with_identity():
    result = _make_result(observables=[])
    bundle = normalize(result)
    objects = bundle.get("objects", [])
    # At minimum: the Identity
    assert len(objects) >= 1
    assert objects[0]["type"] == "identity"
