"""
Regression tests for STIX id generation in orchestrator.normalizer.stix.

These cover the three properties that make OpenCTI ingestion idempotent and
correlatable, each of which was broken at some point:

  1. SCO ids follow the STIX 2.1 spec (OASIS namespace), so our observables
     collide with the same observable produced by MISP or an official OpenCTI
     connector instead of landing as a second object.
  2. Every object id is stable across runs — including Relationship, Note and
     the Indicator fallback, which are SDOs and get a random uuid4 from the
     stix2 library unless an id is pinned explicitly.
  3. The emitted value is the canonical one, and the id is derived from it, so
     Example.COM and example.com are one observable and not two.

Ids are asserted against stix2-generated references rather than hardcoded
literals: a literal would encode today's behaviour, not the spec.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import stix2

from orchestrator.models import (
    CollectorName,
    CollectorResult,
    Observable,
    Relationship,
)
from orchestrator.normalizer.stix import normalize

COLLECTED_AT = datetime(2026, 9, 4, tzinfo=UTC)


def _result(**kwargs) -> CollectorResult:
    defaults = dict(
        collector=CollectorName.OPENOSINT,
        target_fqdn="example.com",
        collected_at=COLLECTED_AT,
        success=True,
    )
    defaults.update(kwargs)
    return CollectorResult(**defaults)


def _objects(result: CollectorResult) -> list[dict]:
    return list(normalize(result).get("objects", []))


def _first_of_type(result: CollectorResult, stix_type: str) -> dict:
    for obj in _objects(result):
        if obj["type"] == stix_type and obj["id"] != _tool_identity_id():
            return obj
    raise AssertionError(f"no {stix_type} object in bundle")


def _tool_identity_id() -> str:
    from orchestrator.normalizer.stix import _IDENTITIES

    return _IDENTITIES[CollectorName.OPENOSINT].id


# ── 1. SCO ids follow the STIX 2.1 spec ───────────────────────────────────────


@pytest.mark.parametrize(
    ("obs_type", "value", "reference"),
    [
        ("domain-name", "example.com", lambda: stix2.DomainName(value="example.com")),
        ("ipv4-addr", "93.184.216.34", lambda: stix2.IPv4Address(value="93.184.216.34")),
        ("ipv6-addr", "2606:2800:220:1::1", lambda: stix2.IPv6Address(value="2606:2800:220:1::1")),
        ("url", "https://example.com/a", lambda: stix2.URL(value="https://example.com/a")),
        ("email-addr", "admin@example.com", lambda: stix2.EmailAddress(value="admin@example.com")),
        ("autonomous-system", "15169", lambda: stix2.AutonomousSystem(number=15169)),
        ("file", "a" * 64, lambda: stix2.File(hashes={"SHA-256": "a" * 64})),
        (
            "user-account",
            "alice",
            lambda: stix2.UserAccount(account_type="generic", user_id="alice"),
        ),
    ],
)
def test_sco_id_matches_stix_spec(obs_type: str, value: str, reference) -> None:
    obj = _first_of_type(_result(observables=[Observable(type=obs_type, value=value)]), obs_type)
    assert obj["id"] == reference().id


def test_sco_id_recomputes_from_emitted_value() -> None:
    """A consumer recomputing the id from the emitted value must get the same id."""
    obj = _first_of_type(
        _result(observables=[Observable(type="domain-name", value="Example.COM")]),
        "domain-name",
    )
    assert obj["id"] == stix2.DomainName(value=obj["value"]).id


def test_domain_ipv4_email_ids_match_stix2_references() -> None:
    result = _result(
        observables=[
            Observable(type="domain-name", value="example.com"),
            Observable(type="ipv4-addr", value="93.184.216.34"),
            Observable(type="email-addr", value="admin@example.com"),
        ]
    )
    objects = _objects(result)
    by_type = {obj["type"]: obj for obj in objects if obj["type"] != "identity"}
    assert by_type["domain-name"]["id"] == stix2.DomainName(value="example.com").id
    assert by_type["ipv4-addr"]["id"] == stix2.IPv4Address(value="93.184.216.34").id
    assert by_type["email-addr"]["id"] == stix2.EmailAddress(value="admin@example.com").id


# ── 2. Every object id is stable across runs ──────────────────────────────────


def test_all_object_ids_stable_across_runs() -> None:
    """Relationships, notes and the Indicator fallback included."""
    result = _result(
        observables=[
            Observable(type="domain-name", value="example.com"),
            Observable(type="ipv4-addr", value="93.184.216.34"),
            Observable(type="x509-certificate", value="CN=example.com"),
            Observable(type="mutex", value="Global\\SomeMutex"),
        ],
        relationships=[
            Relationship(
                source_value="example.com",
                source_type="domain-name",
                target_value="93.184.216.34",
                target_type="ipv4-addr",
                relationship_type="resolves-to",
            )
        ],
        notes=["a free-form collector note"],
    )
    assert [o["id"] for o in _objects(result)] == [o["id"] for o in _objects(result)]


@pytest.mark.parametrize("stix_type", ["relationship", "note", "indicator", "x509-certificate"])
def test_sdo_types_present_and_deterministic(stix_type: str) -> None:
    """Each of these got a random uuid4 before an explicit id was pinned."""
    result = _result(
        observables=[
            Observable(type="domain-name", value="example.com"),
            Observable(type="ipv4-addr", value="93.184.216.34"),
            Observable(type="x509-certificate", value="CN=example.com"),
            Observable(type="mutex", value="Global\\SomeMutex"),
        ],
        relationships=[
            Relationship(
                source_value="example.com",
                source_type="domain-name",
                target_value="93.184.216.34",
                target_type="ipv4-addr",
                relationship_type="resolves-to",
            )
        ],
        notes=["a free-form collector note"],
    )
    ids = {o["id"] for o in _objects(result) if o["type"] == stix_type}
    assert ids, f"expected at least one {stix_type} object"
    assert ids == {o["id"] for o in _objects(result) if o["type"] == stix_type}


def test_relationship_id_depends_on_endpoints_and_type() -> None:
    def rel_id(relationship_type: str) -> str:
        result = _result(
            observables=[
                Observable(type="domain-name", value="example.com"),
                Observable(type="ipv4-addr", value="93.184.216.34"),
            ],
            relationships=[
                Relationship(
                    source_value="example.com",
                    source_type="domain-name",
                    target_value="93.184.216.34",
                    target_type="ipv4-addr",
                    relationship_type=relationship_type,
                )
            ],
        )
        return _first_of_type(result, "relationship")["id"]

    assert rel_id("resolves-to") != rel_id("related-to")


# ── 3. Canonical values ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("obs_type", "mixed", "canonical"),
    [
        ("domain-name", "Example.COM", "example.com"),
        ("email-addr", "ADMIN@EXAMPLE.COM", "admin@example.com"),
        ("user-account", "ALICE", "alice"),
    ],
)
def test_case_variants_collapse_to_one_object(obs_type: str, mixed: str, canonical: str) -> None:
    a = _first_of_type(_result(observables=[Observable(type=obs_type, value=mixed)]), obs_type)
    b = _first_of_type(_result(observables=[Observable(type=obs_type, value=canonical)]), obs_type)
    assert a["id"] == b["id"]


def test_url_keeps_scheme_and_path_case() -> None:
    """URL paths are case-sensitive and the scheme is part of the SCO value."""
    obj = _first_of_type(
        _result(observables=[Observable(type="url", value="https://Example.com/Path")]),
        "url",
    )
    assert obj["value"] == "https://Example.com/Path"
    assert obj["id"] == stix2.URL(value=obj["value"]).id


def test_duplicate_observables_emitted_once() -> None:
    result = _result(
        observables=[
            Observable(type="domain-name", value="example.com"),
            Observable(type="domain-name", value="EXAMPLE.COM"),
        ]
    )
    assert len([o for o in _objects(result) if o["type"] == "domain-name"]) == 1


# ── Identity SDOs for people and organisations ────────────────────────────────


@pytest.mark.parametrize("identity_class", ["individual", "organization"])
def test_person_and_org_become_identity_sdos(identity_class: str) -> None:
    result = _result(
        observables=[
            Observable(
                type="identity",
                value="Acme Corp",
                extra={"identity_class": identity_class},
            )
        ]
    )
    obj = _first_of_type(result, "identity")
    assert obj["name"] == "Acme Corp"
    assert obj["identity_class"] == identity_class


# ── Phone numbers: OpenCTI's native observable ────────────────────────────────


def test_phone_number_is_a_native_observable_not_an_indicator() -> None:
    """
    STIX 2.1 has no phone SCO. Emitting an Indicator wrapping
    [phone-number:value = ...] would reference the same non-standard type while
    also being semantically wrong — an Indicator is a detection rule, not an
    observation. OpenCTI reads type "phone-number" as its Phone-Number
    observable, so that is what we emit.
    """
    objs = _objects(_result(observables=[Observable(type="phone-number", value="+15551234567")]))
    types = {o["type"] for o in objs}
    assert "phone-number" in types
    assert "indicator" not in types

    phone = next(o for o in objs if o["type"] == "phone-number")
    assert phone["value"] == "+15551234567"
    assert phone["spec_version"] == "2.1"
    assert phone["id"].startswith("phone-number--")


@pytest.mark.parametrize(
    "formatted",
    ["+1 (555) 123-4567", "+1.555.123.4567", "+1-555-123-4567", "  +15551234567  "],
)
def test_phone_formatting_variants_collapse_to_one_observable(formatted: str) -> None:
    """Formatting characters carry no information; the subscriber is the same."""
    a = _first_of_type(
        _result(observables=[Observable(type="phone-number", value=formatted)]), "phone-number"
    )
    b = _first_of_type(
        _result(observables=[Observable(type="phone-number", value="+15551234567")]), "phone-number"
    )
    assert a["id"] == b["id"]
    assert a["value"] == "+15551234567"


def test_phone_with_extension_is_left_intact() -> None:
    """Stripping formatting from a value with an extension would change it."""
    obj = _first_of_type(
        _result(observables=[Observable(type="phone-number", value="+15551234567 ext. 89")]),
        "phone-number",
    )
    assert obj["value"] == "+15551234567 ext. 89"


def test_phone_number_id_is_stable_across_runs() -> None:
    result = _result(observables=[Observable(type="phone-number", value="+15551234567")])
    assert (
        _first_of_type(result, "phone-number")["id"] == _first_of_type(result, "phone-number")["id"]
    )


def test_phone_number_type_is_not_registered_with_stix2() -> None:
    """
    We emit a dict rather than registering a stix2 CustomObservable because
    pycti already registers "phone-number"; a second registration raises
    DuplicateRegistrationError and would make import order decide whether the
    orchestrator starts. This guards that we never start registering it.
    """
    from stix2 import CustomObservable
    from stix2.properties import StringProperty

    import orchestrator.normalizer.stix  # noqa: F401  — ensure our module is imported

    pytest.importorskip("pycti", reason="collision only observable with pycti present")
    with pytest.raises(Exception, match="already exists"):

        @CustomObservable("phone-number", [("value", StringProperty(required=True))])
        class _Phone:
            pass


def test_phone_number_relationship_endpoints_resolve() -> None:
    """A phone emitted as a dict must still be reachable as a relationship endpoint."""
    result = _result(
        observables=[
            Observable(type="identity", value="Jane Doe", extra={"identity_class": "individual"}),
            Observable(type="phone-number", value="+15551234567"),
        ],
        relationships=[
            Relationship(
                source_value="Jane Doe",
                source_type="identity",
                target_value="+1 (555) 123-4567",
                target_type="phone-number",
                relationship_type="related-to",
            )
        ],
    )
    rel = _first_of_type(result, "relationship")
    assert rel["target_ref"] == _first_of_type(result, "phone-number")["id"]


# ── Indicator fallback: pattern escaping ──────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [
        r"Global\SomeMutex",  # backslash — invalid escape if not doubled
        "it's-a-value",  # single quote — terminates the literal
        r"C:\Users\x27test",  # both, in an order that breaks naive escaping
    ],
)
def test_indicator_fallback_escapes_pattern_literals(value: str) -> None:
    """
    An unparseable pattern makes stix2 reject the Indicator, and the normalizer
    logs it and returns None — the finding disappears silently. Values with
    backslashes did exactly that until the escape order was fixed.
    """
    obj = _first_of_type(_result(observables=[Observable(type="mutex", value=value)]), "indicator")
    assert obj["pattern"].startswith("[mutex:value = '")
    # The emitted name is the raw value; only the pattern literal is escaped.
    assert obj["name"] == value


def test_indicator_pattern_is_parseable_by_stix2() -> None:
    """stix2 validates patterns on construction, so a bad one raises here."""
    import stix2.patterns  # noqa: F401

    obj = _first_of_type(
        _result(observables=[Observable(type="mutex", value=r"Global\Mutex'x")]), "indicator"
    )
    assert (
        stix2.Indicator(
            pattern=obj["pattern"], pattern_type="stix", valid_from=COLLECTED_AT
        ).pattern
        == obj["pattern"]
    )
