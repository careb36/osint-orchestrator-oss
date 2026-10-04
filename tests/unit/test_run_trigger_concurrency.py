from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

import orchestrator.api as api_mod
from orchestrator.api import app
from orchestrator.models import Target


def _target(target_id: str, *, enabled: bool = True, language: str | None = "en") -> Target:
    return Target(
        id=target_id,
        enabled=enabled,
        fqdn=f"{target_id}.example.com",
        authorization="self-owned",
        purpose="test",
        language=language,
    )


def test_trigger_run_returns_409_when_target_already_has_an_active_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api_mod, "_load_targets", lambda: [_target("alpha", language="en")])
    create_mock = AsyncMock(return_value=None)
    monkeypatch.setattr(api_mod, "create_pending_run", create_mock)

    with TestClient(app) as client:
        response = client.post("/targets/alpha/run")

    assert response.status_code == 409
    assert response.json()["detail"] == "An active run already exists for target 'alpha'"
    create_mock.assert_awaited_once_with("alpha")
