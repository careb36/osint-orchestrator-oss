"""
The shipped targets.example.yaml must stay loadable.

It is the first thing an operator copies, so a field renamed in models.py
without updating the example turns into a validation error on someone's very
first run — long after the change that caused it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from orchestrator.i18n import SUPPORTED_LANGUAGES, resolve_language
from orchestrator.models import Target

EXAMPLE = Path(__file__).resolve().parents[2] / "targets.example.yaml"


def _raw_targets() -> list[dict]:
    data = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8")) or {}
    targets = data.get("targets", [])
    assert targets, "targets.example.yaml must ship at least one example"
    return targets


def test_every_example_target_validates() -> None:
    for raw in _raw_targets():
        Target(**raw)


def test_mandatory_audit_fields_are_present() -> None:
    """authorization and purpose are the audit trail; an example without them
    teaches the wrong habit."""
    for raw in _raw_targets():
        assert raw.get("authorization", "").strip()
        assert raw.get("purpose", "").strip()


def test_declared_languages_are_supported() -> None:
    for raw in _raw_targets():
        language = Target(**raw).language
        if language is not None:
            assert language in SUPPORTED_LANGUAGES


def test_example_covers_both_override_and_inheritance() -> None:
    """One target should pin a language and one should inherit, so the example
    documents both halves of the resolution order."""
    languages = [Target(**raw).language for raw in _raw_targets()]
    assert any(lang is not None for lang in languages), "no target pins a language"
    assert any(lang is None for lang in languages), "no target inherits the global"


@pytest.mark.parametrize("raw", _raw_targets(), ids=lambda raw: raw["id"])
def test_investigation_type_is_a_real_entity_kind(raw: dict) -> None:
    entity_kind = pytest.importorskip("openosint.investigate").EntityKind
    from orchestrator.collectors.openosint import _INVESTIGATION_TYPE_TO_KIND

    declared = Target(**raw).collectors.openosint.investigation_type
    assert declared in _INVESTIGATION_TYPE_TO_KIND
    assert _INVESTIGATION_TYPE_TO_KIND[declared] in {k.value for k in entity_kind}


def test_resolution_of_example_targets_is_supported() -> None:
    for raw in _raw_targets():
        assert resolve_language(Target(**raw).language) in SUPPORTED_LANGUAGES
