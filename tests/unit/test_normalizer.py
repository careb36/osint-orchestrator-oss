"""Unit tests for orchestrator.normalizer.stix"""

from __future__ import annotations

import json
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


def test_empty_notes_skipped():
    result = _make_result(observables=[], notes=["", "   ", ""])
    bundle = normalize(result)
    notes = [o for o in bundle.get("objects", []) if o["type"] == "note"]
    assert len(notes) == 0


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


def test_autonomous_system_non_numeric_fallback():
    result = _make_result(observables=[Observable(type="autonomous-system", value="not-a-number")])
    bundle = normalize(result)
    ases = [o for o in bundle.get("objects", []) if o.get("type") == "autonomous-system"]
    assert len(ases) == 1
    assert ases[0]["number"] == 0


# ── Tests: empty result ───────────────────────────────────────────────────────


def test_empty_observables_returns_bundle_with_identity():
    result = _make_result(observables=[])
    bundle = normalize(result)
    objects = bundle.get("objects", [])
    # At minimum: the Identity
    assert len(objects) >= 1
    assert objects[0]["type"] == "identity"
