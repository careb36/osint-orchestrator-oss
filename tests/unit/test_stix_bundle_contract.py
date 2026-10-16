"""The external STIX producers' intake contract against its JSON Schema.

Validates a bundle shaped like the ``investigation-assistant`` producer's output
against ``orchestrator/contracts/stix-bundle.schema.json`` (jsonschema, draft
2020-12). The schema is the pinned copy the producer publishes (its
``IA-ADR-005``); when its version moves, this test forces ``SCHEMA_VERSION``
and the copy to be updated together.

``engine_bundle.stix.json`` reproduces the engine's real shape (labels,
confidence, object_marking_refs, x_* properties, notes with
external_references). It is richer than ``external_bundle.stix.json``, which is
generic and only exercises parsing the OpenCTI SCOs in ``test_ingest_bundle.py``.

Every negative case starts from the valid fixture and changes one thing, so it
fails on the constraint it names and not on some unrelated malformed field.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from orchestrator.contracts import SCHEMA_VERSION, load_schema

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "engine_bundle.stix.json"


def _load() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _validate(bundle: dict[str, Any]) -> None:
    jsonschema.validate(instance=bundle, schema=load_schema())


def test_schema_is_the_pinned_version() -> None:
    assert SCHEMA_VERSION == "1.0.0"
    assert load_schema()["x-contract-version"] == SCHEMA_VERSION


def test_the_producer_fixture_satisfies_the_schema() -> None:
    _validate(_load())


def test_the_schema_rejects_a_bank_account_without_iban() -> None:
    bundle = _load()
    account = next(o for o in bundle["objects"] if o["type"] == "bank-account")
    changed = {**account}
    del changed["iban"]
    with pytest.raises(jsonschema.ValidationError) as excinfo:
        _validate({**bundle, "objects": [changed]})
    assert list(excinfo.value.absolute_path)[:2] == ["objects", 0]


def test_the_schema_rejects_an_object_of_unknown_type() -> None:
    bundle = _load()
    identity = next(o for o in bundle["objects"] if o["type"] == "identity")
    unknown = {
        **identity,
        "type": "unknown-thing",
        "id": identity["id"].replace("identity--", "unknown-thing--", 1),
    }
    with pytest.raises(jsonschema.ValidationError) as excinfo:
        _validate({**bundle, "objects": [unknown]})
    # The bundle's own id is valid, so the rejection is the object's, not the id's.
    assert list(excinfo.value.absolute_path)[:2] == ["objects", 0]
