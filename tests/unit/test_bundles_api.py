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
OBJECTS = 7  # marking-definition + two identities + bank-account + text + relationship + note


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
    account = next(o for o in bundle["objects"] if o["type"] == "bank-account")
    del account["iban"]
    res = test_client.post("/bundles", json=bundle)
    assert res.status_code == 422
    assert fake.ingested == []


def test_conflicts_when_opencti_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "opencti_enabled", False)
    with TestClient(app) as test_client:
        res = test_client.post("/bundles", json=_bundle())
    assert res.status_code == 409


class _FailingSink:
    """Raises what ``OpenCTISink.ingest_async`` lets out once retries are spent."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    async def ingest_async(self, bundle: Any, **_: Any) -> None:
        raise self.exc


def _client_with_sink(monkeypatch: pytest.MonkeyPatch, sink: Any) -> TestClient:
    monkeypatch.setattr(settings, "opencti_enabled", True)
    monkeypatch.setattr(api_module, "OpenCTISink", lambda: sink)
    return TestClient(app, raise_server_exceptions=False)


def test_malformed_json_is_400_not_500(client) -> None:
    test_client, fake = client
    res = test_client.post(
        "/bundles", content=b"{not json", headers={"content-type": "application/json"}
    )
    assert res.status_code == 400
    assert res.json()["detail"].startswith("El cuerpo no es JSON válido")
    assert fake.ingested == []


def test_contract_violation_detail_is_localised(client, monkeypatch: pytest.MonkeyPatch) -> None:
    test_client, _ = client
    monkeypatch.setattr(settings, "orchestrator_language", "en")
    res = test_client.post("/bundles", json={"type": "bundle"})
    assert res.status_code == 422
    assert res.json()["detail"].startswith("The bundle does not satisfy the contract")


def test_a_failed_ingest_is_502_with_the_sink_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    from orchestrator.sinks import OpenCTIIngestError

    sink = _FailingSink(
        OpenCTIIngestError("1 of 7 objects rejected: text--x (text)", transient=False)
    )
    with _client_with_sink(monkeypatch, sink) as test_client:
        res = test_client.post("/bundles", json=_bundle())
    assert res.status_code == 502
    assert "text--x (text)" in res.json()["detail"]


def test_an_unreachable_opencti_is_503_without_leaking_the_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import requests

    sink = _FailingSink(requests.ConnectionError("http://opencti.internal:8080 refused"))
    with _client_with_sink(monkeypatch, sink) as test_client:
        res = test_client.post("/bundles", json=_bundle())
    assert res.status_code == 503
    assert "opencti.internal" not in res.json()["detail"]
