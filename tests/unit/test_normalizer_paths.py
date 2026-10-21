"""
Inputs the STIX normalizer must drop or degrade instead of failing the bundle.

One bad observable, relationship or note must cost only that object: the
rest of the collector's findings still reach OpenCTI and the report.
"""

from __future__ import annotations

import logging

import pytest
import stix2

import orchestrator.normalizer.stix as stix_module
from orchestrator.models import (
    CollectorName,
    CollectorResult,
    EvidenceQualification,
    Observable,
    Relationship,
)
from orchestrator.normalizer.stix import normalize


def _result(
    observables=(),
    relationships=(),
    notes=(),
    collector: CollectorName = CollectorName.OPENOSINT,
) -> CollectorResult:
    return CollectorResult(
        collector=collector,
        target_fqdn="example.com",
        observables=list(observables),
        relationships=list(relationships),
        notes=list(notes),
        success=True,
    )


def _types(bundle) -> list[str]:
    return [obj["type"] for obj in bundle["objects"]]


def test_blank_observable_value_is_dropped() -> None:
    bundle = normalize(_result([Observable(type="domain-name", value="   ")]))
    assert _types(bundle) == ["identity"]


def test_file_value_that_is_not_a_digest_becomes_an_indicator() -> None:
    """An unnamed File would get a random id; an Indicator keeps it deterministic."""
    first = normalize(_result([Observable(type="file", value="report.pdf")]))
    second = normalize(_result([Observable(type="file", value="report.pdf")]))

    (indicator,) = [o for o in first["objects"] if o["type"] == "indicator"]
    assert indicator["pattern"] == "[file:value = 'report.pdf']"
    assert indicator["id"] == [o for o in second["objects"] if o["type"] == "indicator"][0]["id"]


def test_an_observable_stix2_rejects_is_dropped_and_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def _rejecting(value, custom):
        raise stix2.exceptions.InvalidValueError(stix2.Identity, "value", "rejected")

    monkeypatch.setattr(stix_module, "_phone_number_sco", _rejecting)

    with caplog.at_level(logging.WARNING, logger=stix_module.__name__):
        bundle = normalize(
            _result(
                [
                    Observable(type="phone-number", value="+15555550100"),
                    Observable(type="email-addr", value="admin@example.com"),
                ]
            )
        )

    assert _types(bundle) == ["identity", "email-addr"]
    assert any("Could not build STIX object for phone-number" in r.message for r in caplog.records)


def test_a_relationship_without_a_type_is_dropped_and_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    observables = [
        Observable(type="domain-name", value="a.example.com"),
        Observable(type="domain-name", value="b.example.com"),
    ]
    relationship = Relationship(
        source_value="a.example.com",
        source_type="domain-name",
        target_value="b.example.com",
        target_type="domain-name",
        relationship_type="",
    )

    with caplog.at_level(logging.WARNING, logger=stix_module.__name__):
        bundle = normalize(_result(observables, [relationship]))

    assert _types(bundle) == ["identity", "domain-name", "domain-name"]
    assert any("Could not build STIX Relationship" in r.message for r in caplog.records)


def test_a_note_stix2_rejects_is_dropped_and_the_rest_survives(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    real_note = stix2.Note

    def _note(**kwargs):
        if kwargs["content"] == "poison":
            raise stix2.exceptions.InvalidValueError(stix2.Note, "content", "rejected")
        return real_note(**kwargs)

    monkeypatch.setattr(stix_module.stix2, "Note", _note)

    with caplog.at_level(logging.WARNING, logger=stix_module.__name__):
        bundle = normalize(_result(notes=["poison", "kept"]))

    notes = [o for o in bundle["objects"] if o["type"] == "note"]
    assert [n["content"] for n in notes] == ["kept"]
    assert any("Could not build STIX Note" in r.message for r in caplog.records)


def test_tavily_note_without_a_url_gets_no_qualification_labels() -> None:
    qualification = EvidenceQualification(
        run_id=1,
        target_id="t1",
        url="https://example.com/a",
        title="t",
        category="adverse_media",
        relevance="high",
        confidence=0.9,
        rationale="r",
        provider="p",
        model="m",
    )
    bundle = normalize(
        _result(notes=["Tavily: no public results"], collector=CollectorName.TAVILY),
        qualification_by_url={"https://example.com/a": qualification},
    )

    (note,) = [o for o in bundle["objects"] if o["type"] == "note"]
    assert note["labels"] == ["example.com", "tavily"]
    assert "x_orchestrator_confidence" not in note
