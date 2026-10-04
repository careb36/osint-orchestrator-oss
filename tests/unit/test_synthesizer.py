"""
Unit tests for the Phase 3 synthesizer.

All tests run without network access.  A FakeLLMClient stands in for any
real provider; a fake session-factory replaces the async DB engine.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.synthesizer as synth_module
from orchestrator.config import settings
from orchestrator.models import (
    CollectorName,
    Finding,
    FindingRecord,
    Run,
    RunStatus,
    Target,
)
from orchestrator.reports import (
    CollectorReportResult,
    ReportObservable,
    RunReportData,
    generate_report,
)
from orchestrator.synthesizer import synthesize

# ─── Helpers ─────────────────────────────────────────────────────────────────

_CANONICAL_FINDING = {
    "summary": "El dominio example.com expone servicios web estándar.",
    "new_since_last_run": ["example.com", "1.2.3.4"],
    "risk_level": "low",
    "risk_justification": "No se detectaron indicadores de compromiso.",
    "suggested_pivots": ["Revisar certificados TLS", "Enumerar subdominios"],
}


def _make_engine():
    return create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def _make_session_factory(engine):
    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=True) as session:
            yield session

    return _session


def _make_report_data(
    *,
    target_id: str = "t1",
    run_id: int = 1,
    observables: list[ReportObservable] | None = None,
) -> RunReportData:
    if observables is None:
        observables = [
            ReportObservable(
                stix_id="domain-name--1",
                stix_type="domain-name",
                value="example.com",
                is_new=True,
            ),
            ReportObservable(
                stix_id="ipv4-addr--1",
                stix_type="ipv4-addr",
                value="1.2.3.4",
                is_new=True,
            ),
        ]
    return RunReportData(
        target_id=target_id,
        target_fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        run_id=run_id,
        run_status="success",
        run_started_at=datetime(2026, 9, 8, 12, 0, tzinfo=UTC),
        run_finished_at=datetime(2026, 9, 8, 12, 5, tzinfo=UTC),
        collector_results=[
            CollectorReportResult(collector="openosint", success=True, observable_count=2)
        ],
        bundles=[],
        observables=observables,
        errors=[],
    )


def _target(*, llm: str = "local", language: str | None = None) -> Target:
    return Target(
        id="t1",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        llm=llm,
        language=language,
    )


# ─── FakeLLMClient ────────────────────────────────────────────────────────────


class _ReportsModel:
    """Mixin giving the fakes the ``model_for_route`` half of the LLMClient protocol."""

    served_model = "fake-model"
    provider = "fake"

    def model_for_route(self, route: str) -> str:
        _ = route
        return self.served_model


class FakeLLMClient(_ReportsModel):
    """Returns a canonical JSON Finding on every call."""

    def __init__(self, response: str | None = None):
        self.calls: list[tuple[str, str]] = []
        self._response = response or json.dumps(_CANONICAL_FINDING)

    async def complete(
        self,
        system: str,
        user: str,
        *,
        timeout: float,
        model_route: str = "reasoning",
        response_schema: dict | None = None,
    ) -> str:
        _ = model_route
        _ = response_schema
        self.calls.append((system, user))
        return self._response


class FailingLLMClient(_ReportsModel):
    """Always raises asyncio.TimeoutError to simulate a timeout."""

    async def complete(
        self,
        system: str,
        user: str,
        *,
        timeout: float,
        model_route: str = "reasoning",
        response_schema: dict | None = None,
    ) -> str:
        _ = model_route
        _ = response_schema

        raise TimeoutError("LLM timed out")


class MalformedLLMClient(_ReportsModel):
    """Returns non-JSON on first call, valid JSON on the second (repair)."""

    def __init__(self, *, always_bad: bool = False):
        self.calls = 0
        self._always_bad = always_bad

    async def complete(
        self,
        system: str,
        user: str,
        *,
        timeout: float,
        model_route: str = "reasoning",
        response_schema: dict | None = None,
    ) -> str:
        _ = model_route
        _ = response_schema
        self.calls += 1
        if self.calls == 1 or self._always_bad:
            return "This is not JSON at all."
        return json.dumps(_CANONICAL_FINDING)


# ─── In-memory DB fixture ─────────────────────────────────────────────────────


@pytest.fixture()
async def mem_db(monkeypatch: pytest.MonkeyPatch):
    """
    Yield (engine, session_factory) for an in-memory SQLite DB and monkeypatch
    orchestrator.synthesizer.get_session to use it.
    """
    engine = _make_engine()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_factory = _make_session_factory(engine)
    monkeypatch.setattr(synth_module, "get_session", session_factory)
    return engine, session_factory


# ─── Test 1: canonical response → correct Finding, persisted ─────────────────


@pytest.mark.asyncio
async def test_fake_client_produces_correct_finding_and_persists(
    mem_db,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine, session_factory = mem_db
    target = _target()
    report_data = _make_report_data()

    fake_client = FakeLLMClient()
    monkeypatch.setattr(
        "orchestrator.synthesizer.providers.get_client",
        lambda t: fake_client,
    )
    # Also patch get_client in the synthesizer namespace used at call-time.
    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: fake_client)

    finding, _ = await synthesize(target, 1, report_data)

    assert finding is not None
    assert finding.risk_level == "low"
    assert finding.summary == _CANONICAL_FINDING["summary"]
    assert finding.new_since_last_run == _CANONICAL_FINDING["new_since_last_run"]
    assert finding.suggested_pivots == _CANONICAL_FINDING["suggested_pivots"]

    # Check persistence
    async with session_factory() as session:
        result = await session.exec(select(FindingRecord).where(FindingRecord.run_id == 1))
        record = result.first()
    assert record is not None
    assert record.risk_level == "low"
    assert json.loads(record.new_since_last_run) == _CANONICAL_FINDING["new_since_last_run"]
    # The persisted model is the one the client reports it served, not the
    # route resolution: Ollama ignores the route and serves OLLAMA_MODEL.
    assert record.model == FakeLLMClient.served_model
    assert record.provider == FakeLLMClient.provider

    # Check report.md contains the synthesis section
    report_path = await generate_report(report_data, report_dir=str(tmp_path), finding=finding)
    text = report_path.read_text(encoding="utf-8")
    assert "## Síntesis" in text
    assert _CANONICAL_FINDING["summary"] in text
    assert "`low`" in text
    assert "Revisar certificados TLS" in text


# ─── Test 2: malformed response → retry → second bad → unknown finding ────────


@pytest.mark.asyncio
async def test_malformed_response_retries_and_falls_back_to_unknown(
    mem_db,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, session_factory = mem_db

    # Create a Run so _annotate_run_error has something to update.
    async with session_factory() as session:
        run = Run(target_id="t1", started_at=datetime.now(UTC), status=RunStatus.RUNNING)
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

    bad_client = MalformedLLMClient(always_bad=True)
    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: bad_client)

    finding, _ = await synthesize(_target(), run_id, _make_report_data(run_id=run_id))

    assert finding is not None
    assert finding.risk_level == "unknown"
    # The run must not be marked failed.
    async with session_factory() as session:
        run_db = await session.get(Run, run_id)
    assert run_db is not None
    assert run_db.status == RunStatus.RUNNING  # unchanged by synthesizer


@pytest.mark.asyncio
async def test_malformed_first_then_valid_on_retry(
    mem_db,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, session_factory = mem_db
    client = MalformedLLMClient(always_bad=False)
    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: client)

    finding, _ = await synthesize(_target(), 1, _make_report_data())

    assert finding is not None
    assert finding.risk_level == "low"
    assert client.calls == 2


@pytest.mark.asyncio
async def test_retry_success_raw_response_is_second_call(
    mem_db,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the retry succeeds, FindingRecord.raw_response must be the second
    (valid) response, not the first invalid one."""
    _, session_factory = mem_db

    first_bad = "definitely not json"
    second_good = json.dumps(_CANONICAL_FINDING)

    class TwoCallClient(_ReportsModel):
        calls = 0

        async def complete(
            self,
            system: str,
            user: str,
            *,
            timeout: float,
            model_route: str = "reasoning",
            response_schema: dict | None = None,
        ) -> str:
            _ = model_route
            _ = response_schema
            self.calls += 1
            return first_bad if self.calls == 1 else second_good

    client = TwoCallClient()
    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: client)

    finding, _ = await synthesize(_target(), 1, _make_report_data())
    assert finding is not None
    assert finding.risk_level == "low"

    async with session_factory() as session:
        result = await session.exec(select(FindingRecord).where(FindingRecord.run_id == 1))
        record = result.first()
    assert record is not None
    assert record.raw_response == second_good
    assert first_bad not in record.raw_response


# ─── Test 3: timeout → synthesis omitted, Run.error annotated ─────────────────


@pytest.mark.asyncio
async def test_timeout_annotates_run_error_and_returns_none(
    mem_db,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, session_factory = mem_db

    async with session_factory() as session:
        run = Run(target_id="t1", started_at=datetime.now(UTC), status=RunStatus.RUNNING)
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: FailingLLMClient())

    finding, synthesis_status = await synthesize(
        _target(), run_id, _make_report_data(run_id=run_id)
    )

    assert finding is None
    assert synthesis_status == "failed"

    async with session_factory() as session:
        run_db = await session.get(Run, run_id)
    assert run_db is not None
    assert run_db.error is not None
    assert "synthesis" in run_db.error


@pytest.mark.asyncio
async def test_client_without_provider_member_is_a_failed_synthesis(
    mem_db, monkeypatch: pytest.MonkeyPatch
) -> None:
    """synthesize() never raises: a client missing ``provider`` returns ``failed``."""

    class LegacyClient:
        async def complete(self, system, user, *, timeout, **_):
            return json.dumps(_CANONICAL_FINDING)

    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: LegacyClient())
    finding, status = await synthesize(_target(), 1, _make_report_data())
    assert finding is None
    assert status == "failed"


# ─── Test 4: target.llm="local" always uses OllamaClient ─────────────────────


@pytest.mark.asyncio
async def test_local_target_always_uses_ollama_not_remote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When target.llm == "local", get_client must return an OllamaClient
    regardless of settings.llm_provider.  Verify that AnthropicClient is
    never instantiated.
    """
    monkeypatch.setattr(settings, "llm_provider", "anthropic")
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-fake-key")

    anthropic_instantiated = MagicMock()

    from orchestrator.synthesizer.providers.anthropic import AnthropicClient
    from orchestrator.synthesizer.providers.ollama import OllamaClient

    monkeypatch.setattr(
        "orchestrator.synthesizer.providers.anthropic.AnthropicClient",
        lambda: (anthropic_instantiated(), AnthropicClient())[1],
    )

    from orchestrator.synthesizer.providers import get_client

    client = get_client(_target(llm="local"))
    assert isinstance(client, OllamaClient)
    anthropic_instantiated.assert_not_called()


# ─── Test 5: prompt language ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_prompt_language_default_es_and_en_override(
    mem_db,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """User prompt contains 'Respond in es' or 'Respond in en'."""
    _, session_factory = mem_db

    captured_prompts: list[tuple[str, str]] = []

    class CapturingClient(_ReportsModel):
        async def complete(
            self,
            system: str,
            user: str,
            *,
            timeout: float,
            model_route: str = "reasoning",
            response_schema: dict | None = None,
        ) -> str:
            _ = model_route
            _ = response_schema
            captured_prompts.append((system, user))
            return json.dumps(_CANONICAL_FINDING)

    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: CapturingClient())

    # Spanish (default)
    await synthesize(_target(language=None), 1, _make_report_data())
    assert "Respond in es" in captured_prompts[-1][1]

    # English override
    await synthesize(_target(language="en"), 2, _make_report_data(run_id=2))
    assert "Respond in en" in captured_prompts[-1][1]


@pytest.mark.asyncio
async def test_synthesis_calls_reasoning_model_route_when_supported(
    mem_db,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_routes: list[str] = []

    class RouteCapturingClient(_ReportsModel):
        async def complete(
            self,
            system: str,
            user: str,
            *,
            timeout: float,
            model_route: str = "reasoning",
            response_schema: dict | None = None,
        ) -> str:
            captured_routes.append(model_route)
            assert response_schema is not None
            return json.dumps(_CANONICAL_FINDING)

    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: RouteCapturingClient())

    await synthesize(_target(), 1, _make_report_data())

    assert captured_routes == ["reasoning"]


@pytest.mark.asyncio
async def test_authorization_not_in_prompt(
    mem_db,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """target.authorization must NOT appear in the user prompt (privacy)."""
    _, session_factory = mem_db

    captured_prompts: list[str] = []

    class CapturingClient(_ReportsModel):
        async def complete(
            self,
            system: str,
            user: str,
            *,
            timeout: float,
            model_route: str = "reasoning",
            response_schema: dict | None = None,
        ) -> str:
            _ = model_route
            _ = response_schema
            captured_prompts.append(user)
            return json.dumps(_CANONICAL_FINDING)

    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: CapturingClient())

    target = _target()
    await synthesize(target, 1, _make_report_data())

    assert captured_prompts, "No prompt was captured"
    assert target.authorization not in captured_prompts[0]


@pytest.mark.asyncio
async def test_risk_level_always_english_regardless_of_language(
    mem_db,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """risk_level in the persisted Finding must always be an English identifier."""
    _, session_factory = mem_db
    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: FakeLLMClient())

    finding, _ = await synthesize(_target(language="es"), 1, _make_report_data())
    assert finding is not None
    assert finding.risk_level in {"low", "medium", "high", "critical", "unknown"}


# ─── Test 6: truncation ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_truncation_keeps_new_and_respects_max(
    mem_db,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    With 500 observables (50 new + 450 existing) and max=200, the prompt must
    contain all 50 new and no more than 200 total.
    """
    _, session_factory = mem_db

    monkeypatch.setattr(settings, "llm_max_observables_in_prompt", 200)

    new_obs = [
        ReportObservable(
            stix_id=f"domain-name--new-{i}",
            stix_type="domain-name",
            value=f"new-{i}.example.com",
            is_new=True,
        )
        for i in range(50)
    ]
    existing_obs = [
        ReportObservable(
            stix_id=f"ipv4-addr--old-{i}",
            stix_type="ipv4-addr",
            value=f"10.0.{i // 256}.{i % 256}",
            is_new=False,
        )
        for i in range(450)
    ]
    all_obs = new_obs + existing_obs

    captured: list[str] = []

    class CapturingClient(_ReportsModel):
        async def complete(
            self,
            system: str,
            user: str,
            *,
            timeout: float,
            model_route: str = "reasoning",
            response_schema: dict | None = None,
        ) -> str:
            _ = model_route
            _ = response_schema
            captured.append(user)
            return json.dumps(_CANONICAL_FINDING)

    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: CapturingClient())

    report_data = _make_report_data(observables=all_obs)
    await synthesize(_target(), 1, report_data)

    assert captured, "No prompt was captured"
    user_prompt = captured[0]

    # All 50 new observables appear in the prompt.
    for obs in new_obs:
        assert obs.value in user_prompt, f"New observable {obs.value!r} missing from prompt"

    # Count total observable values shown.  We look for occurrences of
    # ".example.com" (new) and "10.0." (existing) patterns.
    import re

    shown_values = re.findall(r"`[^`]+`", user_prompt)
    # The prompt may include the same value in multiple list items; we count
    # unique values that look like observables.
    shown_unique = {v.strip("`") for v in shown_values}
    # At most max_observables total unique observable values appear.
    assert len(shown_unique) <= 200 + 5  # small slack for prompt metadata values


# ─── Test 7: pipeline integration (fake synthesizer) ─────────────────────────


@pytest.mark.asyncio
async def test_pipeline_finding_in_db_and_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Full pipeline with a fake synthesizer: the finding is persisted in the
    DB and appears in the generated report.md.
    """
    import orchestrator.pipeline as pipeline_module
    from orchestrator.pipeline import run_target_pipeline

    engine = _make_engine()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=True) as session:
            yield session

    monkeypatch.setattr(pipeline_module, "get_session", _session)
    monkeypatch.setattr(pipeline_module, "OpenCTISink", AsyncMock)

    class _FakeCollector:
        name = CollectorName.OPENOSINT

        def __init__(self, target):
            pass

        async def collect(self):
            from orchestrator.models import CollectorResult, Observable

            return CollectorResult(
                collector=CollectorName.OPENOSINT,
                target_fqdn="example.com",
                observables=[Observable(type="domain-name", value="example.com")],
                success=True,
            )

    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_FakeCollector(t)])

    # Patch synthesize so we don't need a real LLM; also need to patch the
    # DB session inside synthesize so it uses the in-memory DB.
    monkeypatch.setattr(synth_module, "get_session", _session)

    fixed_finding_holder: list[Finding] = []

    async def _fake_synthesize(target, run_id, report_data):
        f = Finding(
            target_id=target.id,
            run_id=run_id,
            summary="Superficie de ataque mínima detectada.",
            risk_level="low",
            risk_justification="No hay indicadores de compromiso.",
            suggested_pivots=["Revisar subdominios"],
        )
        # Persist via the module-level helper so the DB record exists.
        await synth_module._persist_finding(
            f,
            provider="fake",
            model="fake-model",
            duration_ms=0,
            raw_response="{}",
        )
        fixed_finding_holder.append(f)
        return f, "ok"

    monkeypatch.setattr(pipeline_module, "synthesize", _fake_synthesize)

    target = Target(
        id="pipe-t1",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        report_dir=str(tmp_path),
    )

    async with _session() as session:
        run = Run(
            target_id=target.id,
            started_at=datetime(2026, 9, 8, 12, 0, tzinfo=UTC),
            status=RunStatus.PENDING,
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

    await run_target_pipeline(target, run_id)

    # Finding persisted in DB.
    async with _session() as session:
        result = await session.exec(select(FindingRecord).where(FindingRecord.run_id == run_id))
        record = result.first()
    assert record is not None
    assert record.risk_level == "low"

    # Finding appears in report.md.
    async with _session() as session:
        run_db = await session.get(Run, run_id)
    assert run_db is not None
    assert run_db.report_path is not None
    report_text = Path(run_db.report_path).read_text(encoding="utf-8")
    assert "## Síntesis" in report_text
    assert "Superficie de ataque mínima detectada." in report_text
    assert "`low`" in report_text


# ─── Test: user.txt template does not contain AUTHORIZATION ──────────────────


def test_user_prompt_template_does_not_contain_authorization() -> None:
    """prompts/user.txt must not contain the AUTHORIZATION placeholder."""
    user_txt = (
        Path(__file__).parent.parent.parent
        / "orchestrator"
        / "synthesizer"
        / "prompts"
        / "user.txt"
    )
    content = user_txt.read_text(encoding="utf-8")
    assert "AUTHORIZATION" not in content, (
        "user.txt contains AUTHORIZATION placeholder which could leak sensitive data "
        "to remote LLM providers; remove it."
    )


# ─── Test: skipped synthesis → report renders "skipped" message ──────────────


@pytest.mark.asyncio
async def test_no_provider_synthesize_returns_skipped_status(
    mem_db,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """When no LLM provider is configured, synthesize returns status='skipped'
    and generate_report renders the 'skipped' message (not 'failed' or the
    old 'not implemented' placeholder)."""
    import orchestrator.synthesizer.providers as prov_module

    monkeypatch.setattr(prov_module, "get_client", lambda t: None)

    finding, synthesis_status = await synthesize(_target(), 1, _make_report_data())

    assert finding is None
    assert synthesis_status == "skipped"

    report_path = await generate_report(
        _make_report_data(),
        report_dir=str(tmp_path),
        finding=finding,
        synthesis_status=synthesis_status,
    )
    text = report_path.read_text(encoding="utf-8")
    # Skipped message must appear.
    assert "omitida" in text or "skipped" in text.lower()
    # Neither the old "not implemented" placeholder nor a "failed" message.
    assert "Fase 3" not in text
    assert "not yet implemented" not in text


# ─── Provider selection and model routing ────────────────────────────────────


def test_target_llm_is_validated() -> None:
    """targets.yaml documents `llm` as local | anthropic | openai | nebius; a typo must not
    silently fall through to the global provider."""
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        _target(llm="antrophic")


@pytest.mark.asyncio
async def test_target_llm_nebius_overrides_a_global_openai_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_provider", "openai")
    monkeypatch.setattr(settings, "nebius_api_key", "test-token")
    monkeypatch.setattr(settings, "nebius_base_url", "https://api.tokenfactory.nebius.com/v1")
    from orchestrator.synthesizer.providers import get_client
    from orchestrator.synthesizer.providers.openai_compat import OpenAICompatClient

    client = get_client(_target(llm="nebius"))
    assert isinstance(client, OpenAICompatClient)
    assert client.provider == "nebius"


@pytest.mark.asyncio
async def test_target_llm_anthropic_overrides_a_global_ollama_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-fake-key")
    from orchestrator.synthesizer.providers import get_client
    from orchestrator.synthesizer.providers.anthropic import AnthropicClient

    assert isinstance(get_client(_target(llm="anthropic")), AnthropicClient)


@pytest.mark.asyncio
async def test_target_llm_remote_without_key_is_skipped_not_silently_downgraded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    monkeypatch.setattr(settings, "openai_api_key", "")
    from orchestrator.synthesizer.providers import get_client

    assert get_client(_target(llm="openai")) is None


@pytest.mark.asyncio
async def test_ollama_is_sent_the_ollama_model_not_the_cloud_model(
    monkeypatch: pytest.MonkeyPatch, httpx_mock
) -> None:
    """A `llm: local` target under a cloud global config used to POST the cloud
    model name (e.g. claude-sonnet-4-5) to Ollama, which 404s on every run."""
    import json as _json

    from orchestrator.synthesizer.providers.ollama import OllamaClient

    monkeypatch.setattr(settings, "llm_model", "claude-sonnet-4-5")
    monkeypatch.setattr(settings, "ollama_model", "llama3.2")
    monkeypatch.setattr(settings, "llm_base_url", "http://ollama.test:11434")
    httpx_mock.add_response(json={"message": {"content": "{}"}})

    await OllamaClient().complete("system", "user", timeout=5)

    sent = _json.loads(httpx_mock.get_requests()[0].content)
    assert sent["model"] == "llama3.2"
