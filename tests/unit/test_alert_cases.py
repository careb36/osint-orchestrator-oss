"""Alert cases: opened by the pipeline for every run that meets a rule, with
or without a channel; acknowledged and resolved through the API."""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.alert_cases as cases_module
import orchestrator.alerts as alerts_module
import orchestrator.api as api_mod
import orchestrator.pipeline as pipeline_module
from orchestrator import metrics
from orchestrator.api import app
from orchestrator.config import settings
from orchestrator.models import AlertCase, Finding, RunStatus, Target


@pytest.fixture
async def db(monkeypatch: pytest.MonkeyPatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    monkeypatch.setattr(pipeline_module, "get_session", _session)
    monkeypatch.setattr(cases_module, "get_session", _session)
    monkeypatch.setattr(api_mod, "get_session", _session)
    monkeypatch.setattr(alerts_module, "build_notifiers", lambda language=None: [])
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    yield _session
    await engine.dispose()


def _target(**alerts) -> Target:
    target = Target(id="t1", fqdn="example.com", authorization="self-owned", purpose="test")
    for key, value in alerts.items():
        setattr(target.alerts, key, value)
    return target


async def _dispatch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    target: Target,
    run_id: int = 1,
    run_status: RunStatus = RunStatus.SUCCESS,
    new_rows: int = 0,
    finding: Finding | None = None,
) -> None:
    async def _delta(_run_id: int):
        return [
            {"stix_type": "domain-name", "value": f"n{i}.example.com", "stix_id": f"s{i}"}
            for i in range(new_rows)
        ]

    monkeypatch.setattr(pipeline_module, "get_run_delta", _delta)
    await pipeline_module._dispatch_alerts(
        target=target, run_id=run_id, run_status=run_status, finding=finding, report_path=None
    )


async def _all_cases(db) -> list[AlertCase]:
    async with db() as session:
        return list((await session.exec(select(AlertCase))).all())


def _gauge(state: str) -> float:
    return metrics.sample("osint_orchestrator_alert_cases", {"state": state}) or 0.0


# ─── Opened by the pipeline ───────────────────────────────────────────────────


async def test_a_run_with_new_observables_opens_a_case_even_with_no_channel(
    db, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _dispatch(monkeypatch, target=_target(), new_rows=2)

    cases = await _all_cases(db)
    assert len(cases) == 1
    assert (cases[0].run_id, cases[0].target_id, cases[0].state) == (1, "t1", "open")
    assert (cases[0].reason, cases[0].new_observable_count) == ("new_observables", 2)
    assert _gauge("open") == 1


async def test_dispatching_twice_for_one_run_opens_one_case(
    db, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _dispatch(monkeypatch, target=_target(), new_rows=1)
    await _dispatch(monkeypatch, target=_target(), new_rows=1)

    assert len(await _all_cases(db)) == 1


async def test_risk_level_rule_names_its_reason(db, monkeypatch: pytest.MonkeyPatch) -> None:
    finding = Finding(target_id="t1", run_id=1, summary="s", risk_level="critical")
    await _dispatch(monkeypatch, target=_target(), finding=finding)

    (case,) = await _all_cases(db)
    assert (case.reason, case.risk_level) == ("risk_level", "critical")


async def test_run_failure_opens_a_case_only_when_the_target_asks(
    db, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _dispatch(monkeypatch, target=_target(), run_id=1, run_status=RunStatus.FAILED)
    assert await _all_cases(db) == []

    await _dispatch(
        monkeypatch, target=_target(on_run_failure=True), run_id=2, run_status=RunStatus.FAILED
    )
    (case,) = await _all_cases(db)
    assert (case.run_id, case.reason, case.run_status) == (2, "run_failure", "failed")


async def test_no_rule_no_case(db, monkeypatch: pytest.MonkeyPatch) -> None:
    await _dispatch(monkeypatch, target=_target(), new_rows=0)
    assert await _all_cases(db) == []


# ─── Triage through the API ───────────────────────────────────────────────────


async def _seed_cases(db, count: int) -> list[int]:
    ids = []
    for run_id in range(1, count + 1):
        case = await cases_module.open_case(
            run_id=run_id,
            target_id="t1" if run_id % 2 else "t2",
            run_status="success",
            risk_level="high",
            new_observable_count=run_id,
            reason="new_observables",
        )
        ids.append(case.id)
    return ids


async def test_list_filters_and_pages(db) -> None:
    ids = await _seed_cases(db, 5)
    with TestClient(app, raise_server_exceptions=True) as client:
        everything = client.get("/alerts").json()
        page = client.get("/alerts", params={"limit": 2, "offset": 2}).json()
        by_target = client.get("/alerts", params={"target_id": "t2"}).json()
        bad_state = client.get("/alerts", params={"state": "weird"})

    assert everything["total"] == 5
    assert [row["id"] for row in everything["items"]] == list(reversed(ids))
    assert [row["id"] for row in page["items"]] == [ids[2], ids[1]]
    assert (page["limit"], page["offset"]) == (2, 2)
    assert {row["target_id"] for row in by_target["items"]} == {"t2"}
    assert by_target["total"] == 2
    assert bad_state.status_code == 422


async def test_acknowledge_then_resolve(db) -> None:
    (case_id,) = await _seed_cases(db, 1)
    before = metrics.sample("osint_orchestrator_alert_case_time_to_acknowledge_seconds_count") or 0
    with TestClient(app, raise_server_exceptions=True) as client:
        acked = client.post(f"/alerts/{case_id}/ack", json={"by": "ana", "note": "looking"})
        again = client.post(f"/alerts/{case_id}/ack", json={"by": "ana"})
        open_list = client.get("/alerts", params={"state": "open"}).json()
        resolved = client.post(f"/alerts/{case_id}/resolve", json={"by": "ana", "note": "noise"})
        twice = client.post(f"/alerts/{case_id}/resolve", json={"by": "ana"})
        detail = client.get(f"/alerts/{case_id}").json()

    assert acked.status_code == 200
    assert (acked.json()["state"], acked.json()["acknowledged_by"]) == ("acknowledged", "ana")
    assert acked.json()["acknowledged_at"] is not None
    assert again.status_code == 409
    assert "acknowledged" in again.json()["detail"]
    assert open_list["total"] == 0
    assert resolved.status_code == 200
    assert (detail["state"], detail["resolved_by"], detail["note"]) == ("resolved", "ana", "noise")
    assert twice.status_code == 409
    after = metrics.sample("osint_orchestrator_alert_case_time_to_acknowledge_seconds_count")
    assert after == before + 1
    assert (_gauge("open"), _gauge("acknowledged")) == (0, 0)


async def test_resolve_straight_from_open(db) -> None:
    (case_id,) = await _seed_cases(db, 1)
    with TestClient(app, raise_server_exceptions=True) as client:
        resolved = client.post(f"/alerts/{case_id}/resolve", json={"by": "bo"})
    assert resolved.status_code == 200
    assert resolved.json()["acknowledged_at"] is None


async def test_unknown_case_is_404_and_bad_body_is_422(db) -> None:
    with TestClient(app, raise_server_exceptions=True) as client:
        assert client.get("/alerts/999").status_code == 404
        assert client.post("/alerts/999/ack", json={"by": "x"}).status_code == 404
        assert client.post("/alerts/999/ack", json={"by": ""}).status_code == 422
        assert client.post("/alerts/999/ack", json={"by": "x" * 81}).status_code == 422


async def test_dlq_replay_route_still_resolves(db) -> None:
    """/alerts/dlq/replay must not be shadowed by /alerts/{case_id}."""
    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.post("/alerts/dlq/replay")
    assert response.status_code == 200
    assert response.json()["status"] == "replayed"


async def test_service_raises_for_an_unknown_case(db) -> None:
    with pytest.raises(cases_module.AlertCaseNotFoundError):
        await cases_module.get_case(4242)
    with pytest.raises(cases_module.AlertCaseNotFoundError):
        await cases_module.acknowledge_case(4242, by="ana")
    with pytest.raises(cases_module.AlertCaseNotFoundError):
        await cases_module.resolve_case(4242, by="ana")


async def test_service_refuses_a_second_acknowledgement_and_a_second_resolution(db) -> None:
    (case_id,) = await _seed_cases(db, 1)
    acked = await cases_module.acknowledge_case(case_id, by="ana", note="looking")
    assert (acked.state, acked.acknowledged_by, acked.note) == ("acknowledged", "ana", "looking")
    with pytest.raises(cases_module.AlertCaseStateConflictError) as conflict:
        await cases_module.acknowledge_case(case_id, by="bo")
    assert conflict.value.state == "acknowledged"
    resolved = await cases_module.resolve_case(case_id, by="bo")
    assert (resolved.state, resolved.resolved_by, resolved.note) == ("resolved", "bo", "looking")
    with pytest.raises(cases_module.AlertCaseStateConflictError):
        await cases_module.resolve_case(case_id, by="bo")
