"""Offline acceptance tests for identities, permissions and professional dossiers."""

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select

import orchestrator.database as database
from orchestrator import accounts
from orchestrator.api import app
from orchestrator.config import settings
from orchestrator.models import (
    AlertsConfig,
    DossierEvent,
    DossierReport,
    DossierRun,
    EvidenceQualification,
    Run,
    Target,
    UserAccount,
    UserSession,
)
from orchestrator.pipeline import run_target_pipeline
from tests.unit.test_evidence_qualification import _SimpleCollector

PASSWORD = "test-user-password"
HEADERS = {"X-Requested-With": "XMLHttpRequest"}


@pytest.fixture
async def personal(monkeypatch, tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(settings, "orchestrator_api_key", "test-machine-key")
    monkeypatch.setattr(settings, "orchestrator_cookie_secure", True)
    monkeypatch.setattr(settings, "orchestrator_secret_key", "test-signing-key")
    monkeypatch.setattr(settings, "opencti_enabled", False)
    monkeypatch.setattr(settings, "llm_provider", "openai")
    await accounts.create_account("admin", "Test Administrator", "admin", PASSWORD)
    await accounts.create_account("analyst", "Test Accountant", "accountant", PASSWORD)

    @asynccontextmanager
    async def client(username="analyst"):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://testserver", headers=HEADERS
        ) as browser:
            response = await browser.post(
                "/auth/login", json={"username": username, "password": PASSWORD}
            )
            assert response.status_code == 200
            yield browser

    yield client


async def _source(tmp_path: Path) -> int:
    target = Target(
        id="review-example",
        fqdn="example.com",
        authorization="offline test authorization",
        purpose="offline acceptance test",
        report_dir=str(tmp_path),
        llm="openai",
        alerts=AlertsConfig(enabled=False),
    )

    class Client:
        provider = "test"

        def model_for_route(self, route):
            return "test-" + route

        async def complete(self, *_args, **kwargs):
            if kwargs.get("model_route") == "fast":
                return json.dumps(
                    {
                        "items": [
                            {
                                "index": 0,
                                "category": "adverse_media",
                                "relevance": "high",
                                "confidence": 0.9,
                                "rationale": "Fictitious test entity.",
                            }
                        ]
                    }
                )
            return json.dumps(
                {
                    "summary": "Fictitious assessment",
                    "risk_level": "high",
                    "risk_justification": "Fictitious test.",
                    "new_since_last_run": [],
                    "suggested_pivots": [],
                }
            )

    async with database.get_session() as session:
        run = Run(target_id=target.id)
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id
    await run_target_pipeline(
        target, run_id, collectors=[_SimpleCollector(target)], llm_client=Client()
    )
    return run_id


CASE = {
    "title": "Fictitious review",
    "entity_name": "Example Company",
    "entity_type": "company",
    "identifier": "TEST-1",
    "country": "Test jurisdiction",
    "purpose": "Authorized offline test",
}
FINAL = {
    "risk_level": "medium",
    "conclusion": "Professional conclusion for a fictitious offline test entity.",
    "acknowledge_limitations": True,
}


async def test_personal_login_cookie_csrf_logout_and_no_password_leak(personal):
    async with personal() as browser:
        cookie = browser.cookies.get(accounts.COOKIE_NAME)
        assert cookie
        assert (await browser.get("/auth/me")).json()["display_name"] == "Test Accountant"
        denied = await browser.post("/cases", json=CASE, headers={"X-Requested-With": ""})
        assert denied.status_code == 403
        forged = await browser.post("/cases", json=CASE, headers={"Origin": "https://evil.example"})
        assert forged.status_code == 403
        assert (await browser.post("/auth/logout")).status_code == 200
        assert (await browser.get("/targets")).status_code == 401
    async with database.get_session() as session:
        assert not (await session.exec(select(UserSession))).all()
        user = (
            await session.exec(select(UserAccount).where(UserAccount.username == "analyst"))
        ).one()
        assert user.password_hash != PASSWORD and accounts.verify_password(
            PASSWORD, user.password_hash
        )


async def test_accountants_cannot_administer_or_impersonate_staff(personal):
    async with personal() as browser:
        assert (await browser.get("/accounts")).status_code == 403
        for path in (
            "/scheduler/reload",
            "/opencti/outbox/replay",
            "/alerts/dlq/replay",
            "/bundles",
        ):
            assert (await browser.post(path, json={})).status_code == 403
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app),
        base_url="https://testserver",
        headers={"X-API-Key": "test-machine-key"},
    ) as machine:
        assert (await machine.get("/targets")).status_code == 200
        assert (await machine.post("/cases", json=CASE)).status_code == 401


async def test_admin_creates_and_revokes_accounts_without_professional_approval(personal):
    async with personal("admin") as admin, personal() as accountant:
        users = await admin.get("/accounts")
        assert users.status_code == 200 and "password" not in users.text
        created = await admin.post(
            "/accounts",
            json={
                "username": "other",
                "display_name": "Other Accountant",
                "role": "accountant",
                "password": PASSWORD,
            },
        )
        assert created.status_code == 201
        assert (
            await admin.post(
                "/accounts",
                json={"username": "other", "display_name": "Other", "password": PASSWORD},
            )
        ).status_code == 409
        me = (await accountant.get("/auth/me")).json()
        assert (
            await admin.post(f"/accounts/{me['id']}", json={"active": False})
        ).status_code == 200
        assert (await accountant.get("/auth/me")).status_code == 401
        admin_id = (await admin.get("/auth/me")).json()["id"]
        assert (
            await admin.post(f"/accounts/{admin_id}", json={"active": False})
        ).status_code == 409
        case = (await admin.post("/cases", json=CASE)).json()
        assert (
            await admin.post(f"/cases/{case['id']}/finalize", json={**FINAL, "revision": 1})
        ).status_code == 403


async def test_password_change_revokes_all_sessions(personal):
    async with personal() as first, personal() as second:
        response = await first.post(
            "/auth/password",
            json={"current_password": PASSWORD, "password": "test-changed-password"},
        )
        assert response.status_code == 200
        assert (await second.get("/auth/me")).status_code == 401


async def test_lockout_rejects_even_correct_password_until_window_passes(personal):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://testserver", headers=HEADERS
    ) as browser:
        for _ in range(5):
            assert (
                await browser.post(
                    "/auth/login", json={"username": "analyst", "password": "test-invalid-password"}
                )
            ).status_code == 401
        assert (
            await browser.post("/auth/login", json={"username": "analyst", "password": PASSWORD})
        ).status_code == 401


async def test_full_dossier_review_export_reopen_and_immutable_versions(personal, tmp_path):
    run_id = await _source(tmp_path)
    async with personal() as browser:
        case = (await browser.post("/cases", json=CASE)).json()
        url = f"/cases/{case['id']}"
        assert (
            await browser.post(url + "/finalize", json={**FINAL, "revision": 1})
        ).status_code == 409
        assert (
            await browser.post(url + "/sources", json={"run_id": run_id, "revision": 1})
        ).status_code == 200
        assert (
            await browser.post(url + "/finalize", json={**FINAL, "revision": 2})
        ).status_code == 409
        data = (await browser.get(url)).json()
        item = data["evidence"][0]
        review = {
            "evidence_id": item["id"],
            "decision": "dismissed",
            "reason": "Fictitious homonym confirmed by identifier",
            "revision": 2,
        }
        assert (await browser.post(url + "/reviews", json=review)).status_code == 200
        assert (await browser.post(url + "/reviews", json=review)).status_code == 409
        assert (
            await browser.post(url + "/finalize", json={**FINAL, "revision": 3})
        ).status_code == 201
        report = (await browser.get(url + "/reports/1")).json()
        assert report["signature_verified"]
        assert "Riesgo determinado por el profesional: medio" in report["markdown"]
        assert report["snapshot"]["professional_decision"]["risk_level"] == "medium"
        assert report["snapshot"]["automated_findings"][0]["risk_level"] == "high"
        assert report["snapshot"]["approved_by"]["username"] == "analyst"
        pdf = await browser.get(url + "/reports/1/pdf")
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")
        assert (
            await browser.post(url + "/reviews", json={**review, "revision": 4})
        ).status_code == 409
        assert (
            await browser.post(
                url + "/reopen",
                json={
                    "revision": 4,
                    "reason": "New information requires professional reassessment",
                },
            )
        ).status_code == 200
        assert (
            await browser.post(
                url + "/finalize",
                json={
                    **FINAL,
                    "revision": 5,
                    "conclusion": "Updated professional conclusion after a documented review.",
                },
            )
        ).status_code == 201
        assert (await browser.get(url + "/reports/1")).json() == report
        assert (await browser.get(url + "/reports/1/pdf")).content == pdf.content
        assert (await browser.get(url + "/reports/2")).json()["signature_verified"]
        events = (await browser.get(url)).json()["events"]
        assert [e["action"] for e in events] == [
            "created",
            "source_attached",
            "evidence_reviewed",
            "finalized",
            "reopened",
            "finalized",
        ]
        assert all(e["actor_name"] == "Test Accountant" for e in events)


async def test_incomplete_or_tampered_sources_block_final_report(personal, tmp_path):
    run_id = await _source(tmp_path)
    async with database.get_session() as session:
        run = await session.get(Run, run_id)
        run.qualification_status = "incomplete"
        session.add(run)
        await session.commit()
    async with personal() as browser:
        case = (await browser.post("/cases", json=CASE)).json()
        url = f"/cases/{case['id']}"
        await browser.post(url + "/sources", json={"run_id": run_id, "revision": 1})
        assert (
            await browser.post(url + "/finalize", json={**FINAL, "revision": 2})
        ).status_code == 409
    async with database.get_session() as session:
        assert not (await session.exec(select(DossierReport))).all()
        assert len((await session.exec(select(DossierEvent))).all()) == 2


async def test_no_anonymous_fallback_when_machine_key_is_empty(personal, monkeypatch):
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://testserver"
    ) as browser:
        assert (await browser.get("/auth/status")).json() == {"personal_access": True}
        assert (await browser.get("/targets")).status_code == 401


async def test_invalid_session_cannot_fall_back_to_a_machine_key(personal):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app),
        base_url="https://testserver",
        headers={"X-API-Key": "test-machine-key"},
    ) as browser:
        browser.cookies.set(accounts.COOKIE_NAME, "test-invalid-session")
        assert (await browser.get("/targets")).status_code == 401


@pytest.mark.parametrize("artifact", ["pdf", "markdown"])
async def test_tampered_source_and_report_are_rejected(personal, tmp_path, artifact):
    run_id = await _source(tmp_path)
    async with personal() as browser:
        case = (await browser.post("/cases", json=CASE)).json()
        url = f"/cases/{case['id']}"
        await browser.post(url + "/sources", json={"run_id": run_id, "revision": 1})
        item = (await browser.get(url)).json()["evidence"][0]
        await browser.post(
            url + "/reviews",
            json={
                "revision": 2,
                "evidence_id": item["id"],
                "decision": "confirmed",
                "reason": "Identity matched against the fictitious source identifier",
            },
        )
        async with database.get_session() as session:
            run = await session.get(Run, run_id)
            path = Path(run.report_path)
        original = path.read_bytes()
        path.write_bytes(original + b"tampered")
        assert (
            await browser.post(url + "/finalize", json={**FINAL, "revision": 3})
        ).status_code == 409
        path.write_bytes(original)
        assert (
            await browser.post(url + "/finalize", json={**FINAL, "revision": 3})
        ).status_code == 201
        async with database.get_session() as session:
            report = (await session.exec(select(DossierReport))).one()
            if artifact == "pdf":
                report.pdf = b"%PDF-test-tampered"
            else:
                report.markdown += "\nAltered professional conclusion"
            session.add(report)
            await session.commit()
        assert not (await browser.get(url + "/reports/1")).json()["signature_verified"]
        assert (await browser.get(url + "/reports/1/pdf")).status_code == 409


@pytest.mark.parametrize("operation", ["login", "password_change"])
async def test_password_reset_invalidates_in_flight_credentials(personal, monkeypatch, operation):
    async with personal("admin") as admin, personal() as accountant:
        user_id = (await accountant.get("/auth/me")).json()["id"]
        checked, resume = asyncio.Event(), asyncio.Event()
        original_to_thread = asyncio.to_thread

        async def pause_password_check(function, *args, **kwargs):
            result = await original_to_thread(function, *args, **kwargs)
            if function is accounts.verify_password and not checked.is_set():
                checked.set()
                await resume.wait()
            return result

        monkeypatch.setattr(accounts.asyncio, "to_thread", pause_password_check)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://testserver", headers=HEADERS
        ) as anonymous:
            request = (
                anonymous.post("/auth/login", json={"username": "analyst", "password": PASSWORD})
                if operation == "login"
                else accountant.post(
                    "/auth/password",
                    json={"current_password": PASSWORD, "password": "test-stale-new-password"},
                )
            )
            pending = asyncio.create_task(request)
            try:
                await asyncio.wait_for(checked.wait(), timeout=5)
                reset = await admin.post(
                    f"/accounts/{user_id}",
                    json={"active": True, "password": "test-admin-reset-password"},
                )
                assert reset.status_code == 200
            finally:
                resume.set()
                response = await pending
            assert response.status_code in (400, 401)
            assert (await accountant.get("/auth/me")).status_code == 401
            assert (await anonymous.get("/auth/me")).status_code == 401
        async with database.get_session() as session:
            user = await session.get(UserAccount, user_id)
            assert accounts.verify_password("test-admin-reset-password", user.password_hash)
            assert not (
                await session.exec(select(UserSession).where(UserSession.user_id == user_id))
            ).all()


@pytest.mark.parametrize("missing", ["source", "evidence", "altered_evidence"])
async def test_missing_linked_data_blocks_final_report(personal, tmp_path, missing):
    run_id = await _source(tmp_path)
    async with personal() as browser:
        case = (await browser.post("/cases", json=CASE)).json()
        url = f"/cases/{case['id']}"
        await browser.post(url + "/sources", json={"run_id": run_id, "revision": 1})
        item = (await browser.get(url)).json()["evidence"][0]
        await browser.post(
            url + "/reviews",
            json={
                "revision": 2,
                "evidence_id": item["id"],
                "decision": "confirmed",
                "reason": "Identity matched against the fictitious source identifier",
            },
        )
        async with database.get_session() as session:
            if missing == "source":
                session.add(DossierRun(dossier_id=case["id"], run_id=999999))
            elif missing == "evidence":
                await session.exec(
                    delete(EvidenceQualification).where(EvidenceQualification.run_id == run_id)
                )
            else:
                evidence = await session.get(EvidenceQualification, item["id"])
                evidence.rationale = "Altered after the source was sealed"
                session.add(evidence)
            await session.commit()
        assert (
            await browser.post(url + "/finalize", json={**FINAL, "revision": 3})
        ).status_code == 409
        async with database.get_session() as session:
            assert not (await session.exec(select(DossierReport))).all()


async def test_dossier_source_survives_operational_retention(personal, tmp_path, monkeypatch):
    from datetime import UTC, datetime, timedelta

    from orchestrator.retention import purge_expired

    run_id = await _source(tmp_path)
    async with personal() as browser:
        case = (await browser.post("/cases", json=CASE)).json()
        await browser.post(f"/cases/{case['id']}/sources", json={"run_id": run_id, "revision": 1})
    async with database.get_session() as session:
        run = await session.get(Run, run_id)
        run.finished_at = datetime.now(UTC) - timedelta(days=100)
        session.add(run)
        await session.commit()
    monkeypatch.setattr(settings, "orchestrator_retention_days", 1)
    summary = await purge_expired()
    assert not summary.errors and summary.runs_deleted == 0
    async with database.get_session() as session:
        run = await session.get(Run, run_id)
        assert run and Path(run.report_path).is_file()


async def test_validation_never_echoes_password_inputs(personal):
    async with personal("admin") as browser:
        response = await browser.post(
            "/accounts",
            json={
                "username": "x",
                "display_name": "Example",
                "password": "tiny",
                "role": "not-a-role",
            },
        )
        assert response.status_code == 422
        assert "tiny" not in response.text
        assert (
            response.json()["detail"]
            == "Revise los campos y las longitudes indicadas antes de continuar."
        )
