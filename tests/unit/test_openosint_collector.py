"""
Tests for the OpenOSINT collector's EntityGraph → CollectorResult mapping.

The graphs here are built with the real openosint types rather than stubs:
the bug this collector replaced was precisely a mapping written against an
imagined interface (a CLI whose flags and subcommands did not exist), which
no stub-based test would have caught. If openosint is not installed these
skip rather than pass vacuously.
"""

from __future__ import annotations

import pytest

from orchestrator.models import CollectorName, Target

correlation = pytest.importorskip(
    "openosint.correlation", reason="openosint (pinned fork) not installed"
)

from orchestrator.collectors.openosint import (  # noqa: E402
    _INVESTIGATION_TYPE_TO_KIND,
    OpenOSINTCollector,
    _ip_stix_type,
)

EntityType = correlation.EntityType
make_entity = correlation.make_entity
OORelationship = correlation.Relationship


def _target(**kwargs) -> Target:
    defaults = dict(id="t1", fqdn="example.com", authorization="self-owned", purpose="test")
    defaults.update(kwargs)
    return Target(**defaults)


def _collector(**kwargs) -> OpenOSINTCollector:
    return OpenOSINTCollector(_target(**kwargs))


def _graph_with(*entities):
    graph = correlation.EntityGraph()
    return graph, [graph.add_entity(e) for e in entities]


# ── Entity type mapping ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("entity_type", "value", "expected"),
    [
        (EntityType.DOMAIN, "example.com", "domain-name"),
        (EntityType.EMAIL, "admin@example.com", "email-addr"),
        (EntityType.USERNAME, "alice", "user-account"),
        (EntityType.URL, "https://example.com/a", "url"),
        (EntityType.ASN, "15169", "autonomous-system"),
        (EntityType.HASH, "a" * 64, "file"),
        (EntityType.IP, "93.184.216.34", "ipv4-addr"),
        (EntityType.IP, "2606:2800:220:1::1", "ipv6-addr"),
        (EntityType.PERSON, "Jane Doe", "identity"),
        (EntityType.ORG, "Acme Corp", "identity"),
    ],
)
def test_entity_types_map_to_stix_types(entity_type, value: str, expected: str) -> None:
    graph, _ = _graph_with(make_entity(entity_type, value, 0.8, "search_dns"))
    result = _collector()._from_graph(graph, "example.com")
    assert [o.type for o in result.observables] == [expected]


def test_ipv6_is_distinguished_from_ipv4() -> None:
    assert _ip_stix_type("93.184.216.34") == "ipv4-addr"
    assert _ip_stix_type("2606:2800:220:1::1") == "ipv6-addr"


def test_unparseable_ip_falls_back_to_ipv4() -> None:
    assert _ip_stix_type("not-an-ip") == "ipv4-addr"


def test_person_and_org_carry_identity_class() -> None:
    graph, _ = _graph_with(
        make_entity(EntityType.PERSON, "Jane Doe", 0.7, "search_github"),
        make_entity(EntityType.ORG, "Acme Corp", 0.7, "search_whois"),
    )
    result = _collector()._from_graph(graph, "example.com")
    classes = {o.value: o.extra["identity_class"] for o in result.observables}
    assert classes == {"Jane Doe": "individual", "Acme Corp": "organization"}


def test_source_tools_are_carried_into_extra() -> None:
    graph, _ = _graph_with(make_entity(EntityType.DOMAIN, "example.com", 0.9, "search_whois"))
    result = _collector()._from_graph(graph, "example.com")
    assert result.observables[0].extra["source_tools"] == ["search_whois"]


# ── Relationships ─────────────────────────────────────────────────────────────


def test_relationships_are_mapped_with_endpoint_types() -> None:
    graph = correlation.EntityGraph()
    dom = graph.add_entity(make_entity(EntityType.DOMAIN, "example.com", 0.9, "search_dns"))
    ip = graph.add_entity(make_entity(EntityType.IP, "93.184.216.34", 0.8, "search_dns"))
    graph.add_relationship(
        OORelationship(source=dom, target=ip, kind="resolves to", source_tool="search_dns")
    )
    result = _collector()._from_graph(graph, "example.com")

    assert len(result.relationships) == 1
    rel = result.relationships[0]
    assert rel.source_type == "domain-name"
    assert rel.target_type == "ipv4-addr"
    # "resolves to" is not a STIX relationship_type; it must be slugified.
    assert rel.relationship_type == "resolves-to"


def test_relationship_to_unmapped_entity_is_dropped() -> None:
    """An edge whose endpoint was dropped must not produce a dangling reference."""
    graph = correlation.EntityGraph()
    dom = graph.add_entity(make_entity(EntityType.DOMAIN, "example.com", 0.9, "search_dns"))
    ip = graph.add_entity(make_entity(EntityType.IP, "93.184.216.34", 0.8, "search_dns"))
    graph.add_relationship(
        OORelationship(source=dom, target=ip, kind="resolves-to", source_tool="search_dns")
    )
    collector = _collector()
    # Simulate a type with no STIX mapping by emptying the mapping table.
    import orchestrator.collectors.openosint as mod

    original = mod._ENTITY_TYPE_TO_STIX.copy()
    try:
        mod._ENTITY_TYPE_TO_STIX.pop("ip")
        result = collector._from_graph(graph, "example.com")
    finally:
        mod._ENTITY_TYPE_TO_STIX.clear()
        mod._ENTITY_TYPE_TO_STIX.update(original)

    assert [o.type for o in result.observables] == ["domain-name"]
    assert result.relationships == []


# ── Result contract ───────────────────────────────────────────────────────────


def test_empty_graph_is_success_with_a_note() -> None:
    """No findings is a successful run, not a failure — but it must be visible."""
    result = _collector()._from_graph(correlation.EntityGraph(), "example.com")
    assert result.success is True
    assert result.observables == []
    assert any("no entities" in n for n in result.notes)


def test_result_carries_collector_name_and_target() -> None:
    graph, _ = _graph_with(make_entity(EntityType.DOMAIN, "example.com", 0.9, "search_dns"))
    result = _collector()._from_graph(graph, "example.com")
    assert result.collector == CollectorName.OPENOSINT
    assert result.target_fqdn == "example.com"


# ── Configuration ─────────────────────────────────────────────────────────────


async def test_graph_mapping_error_is_a_failed_collector_not_an_exception(monkeypatch) -> None:
    """collect() never raises: a malformed graph is reported like any failure."""

    async def _investigate(*_args, **_kwargs):
        return correlation.EntityGraph()

    def _broken(self, graph, fqdn):
        raise AttributeError("'NoneType' object has no attribute 'kind'")

    monkeypatch.setattr(
        OpenOSINTCollector, "_load_api", staticmethod(lambda cfg: (_investigate, None))
    )
    monkeypatch.setattr(OpenOSINTCollector, "_from_graph", _broken)

    result = await _collector().collect()

    assert result.success is False
    assert "graph mapping" in (result.error or "")
    assert "kind" in (result.error or "")


async def test_unknown_investigation_type_fails_loudly() -> None:
    """
    The predecessor silently reported success when it could not run the tool.
    An unusable configuration must surface as a failed run instead.
    """
    target = _target()
    target.collectors.openosint.investigation_type = "not-a-real-type"
    result = await OpenOSINTCollector(target).collect()
    assert result.success is False
    assert "unknown investigation_type" in (result.error or "")


def test_targets_yaml_investigation_types_are_valid_entity_kinds() -> None:
    """Every type we accept in targets.yaml must exist in openosint's EntityKind."""
    entity_kind = pytest.importorskip("openosint.investigate").EntityKind
    valid = {k.value for k in entity_kind}
    assert set(_INVESTIGATION_TYPE_TO_KIND.values()) <= valid


def test_budget_is_built_from_collector_config() -> None:
    target = _target()
    cfg = target.collectors.openosint
    cfg.max_depth, cfg.max_entities = 3, 15
    cfg.max_tool_calls, cfg.tool_timeout_seconds = 25, 45
    _, budget = OpenOSINTCollector(target)._load_api(cfg)
    assert (budget.max_depth, budget.max_entities) == (3, 15)
    assert (budget.max_tool_calls, budget.timeout_seconds) == (25, 45)
