"""Contrato del intake de productores STIX externos contra su JSON Schema.

Valida un bundle con la forma del productor ``investigation-assistant`` contra
``orchestrator/contracts/stix-bundle.schema.json`` (jsonschema, draft 2020-12).
Es la copia fijada del esquema que publica el productor (su ``IA-ADR-005``); si
la versión avanza, este test obliga a actualizar ``SCHEMA_VERSION`` y la copia.

``engine_bundle.stix.json`` reproduce la forma real del motor (labels,
confidence, object_marking_refs, x_*, note con external_references) — más rica
que ``external_bundle.stix.json``, que es genérica y solo prueba el parseo de
los SCO de OpenCTI en ``test_ingest_bundle.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from orchestrator.contracts import SCHEMA_VERSION, load_schema

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "engine_bundle.stix.json"


def _cargar() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _validar(bundle: dict[str, Any]) -> None:
    jsonschema.validate(instance=bundle, schema=load_schema())


def test_esquema_es_la_version_fijada() -> None:
    assert SCHEMA_VERSION == "1.0.0"
    assert load_schema()["x-contract-version"] == SCHEMA_VERSION


def test_el_fixture_del_productor_cumple_el_esquema() -> None:
    _validar(_cargar())


def test_el_esquema_rechaza_bank_account_sin_iban() -> None:
    bundle = _cargar()
    cuenta = next(o for o in bundle["objects"] if o["type"] == "bank-account")
    mutada = {**cuenta}
    del mutada["iban"]
    with pytest.raises(jsonschema.ValidationError):
        _validar({**bundle, "objects": [mutada]})


def test_el_esquema_rechaza_un_objeto_de_tipo_desconocido() -> None:
    with pytest.raises(jsonschema.ValidationError):
        _validar({"type": "bundle", "id": "bundle--" + "0" * 36,
                  "objects": [{"type": "algo-desconocido",
                               "id": "algo-desconocido--" + "0" * 36}]})
