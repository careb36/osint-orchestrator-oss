"""POST /bundles: intake of an external STIX 2.1 bundle (ADR-011)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import orchestrator.api as api_module
from orchestrator.api import app
from orchestrator.config import settings

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "engine_bundle.stix.json"
OBJECTS = 6  # marking-definition + identity + bank-account + text + relationship + note


class _FakeSink:
    def __init__(self) -> None:
        self.ingested: list[tuple[int, str]] = []

    async def ingest_async(
        self,
        bundle: Any,
        *,
        work_name: str = "osint-orchestrator",
        target_id: str | None = None,
    ) -> None:
        self.ingested.append((len(bundle.objects), work_name))


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "opencti_enabled", True)
    fake = _FakeSink()
    monkeypatch.setattr(api_module, "OpenCTISink", lambda: fake)
    with TestClient(app) as test_client:
        yield test_client, fake


def _bundle() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_ingests_a_contract_valid_bundle(client) -> None:
    test_client, fake = client
    res = test_client.post("/bundles", json=_bundle())
    assert res.status_code == 200
    assert fake.ingested == [(OBJECTS, "external-stix")]
    assert res.json() == {"status": "ingested", "work_name": "external-stix", "objects": OBJECTS}


def test_accepts_a_custom_work_name(client) -> None:
    test_client, fake = client
    res = test_client.post("/bundles?work_name=investigation-assistant:demo", json=_bundle())
    assert res.status_code == 200
    assert fake.ingested == [(OBJECTS, "investigation-assistant:demo")]


def test_rejects_a_bundle_that_violates_the_contract(client) -> None:
    test_client, fake = client
    bundle = _bundle()
    cuenta = next(o for o in bundle["objects"] if o["type"] == "bank-account")
    del cuenta["iban"]
    res = test_client.post("/bundles", json=bundle)
    assert res.status_code == 422
    assert fake.ingested == []


def test_conflicts_when_opencti_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "opencti_enabled", False)
    with TestClient(app) as test_client:
        res = test_client.post("/bundles", json=_bundle())
    assert res.status_code == 409
