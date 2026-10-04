from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import httpx
import pytest
from pytest_httpx import HTTPXMock

import orchestrator.api as api_module
from orchestrator import metrics
from orchestrator.config import settings
from orchestrator.synthesizer.providers.openai_compat import preflight_configured_models

METRIC = "osint_orchestrator_llm_model_available"
LOGGER = "orchestrator.synthesizer.providers.openai_compat"


def _metric_value(**labels: str) -> float:
    return metrics.sample(METRIC, labels) or 0.0


@pytest.mark.asyncio
async def test_listed_models_log_info_and_set_gauge_1(
    monkeypatch: pytest.MonkeyPatch, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(settings, "llm_model", "fallback-model")
    monkeypatch.setattr(settings, "llm_model_reasoning", "nvidia/reasoning-model")
    monkeypatch.setattr(settings, "llm_model_fast", "nvidia/fast-model")
    httpx_mock.add_response(
        url="https://api.tokenfactory.nebius.com/v1/models",
        json={"data": [{"id": "nvidia/reasoning-model"}, {"id": "nvidia/fast-model"}]},
    )

    with caplog.at_level("INFO", logger=LOGGER):
        await preflight_configured_models(
            provider_name="nebius",
            api_key="test-token",
            base_url="https://api.tokenfactory.nebius.com/v1",
        )

    logs = [r for r in caplog.records if r.name == LOGGER and r.getMessage() == "LLM model available"]
    assert len(logs) == 2
    assert (
        _metric_value(provider="nebius", model="nvidia/reasoning-model", route="reasoning") == 1.0
    )
    assert _metric_value(provider="nebius", model="nvidia/fast-model", route="fast") == 1.0


@pytest.mark.asyncio
async def test_unlisted_model_logs_error_with_suggestions_and_gauge_0(
    monkeypatch: pytest.MonkeyPatch, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(settings, "llm_model", "fallback-model")
    monkeypatch.setattr(settings, "llm_model_reasoning", "nvidia/nemotron-4-340b-instruct")
    monkeypatch.setattr(settings, "llm_model_fast", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")
    httpx_mock.add_response(
        url="https://api.tokenfactory.nebius.com/v1/models",
        json={
            "data": [
                {"id": "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"},
                {"id": "nvidia/Nemotron-3_5-Lightning"},
            ]
        },
    )

    with caplog.at_level("ERROR", logger=LOGGER):
        await preflight_configured_models(
            provider_name="nebius",
            api_key="test-token",
            base_url="https://api.tokenfactory.nebius.com/v1",
        )

    errors = [r for r in caplog.records if "LLM model not served by provider" in r.getMessage()]
    assert len(errors) == 1
    assert "nvidia/Nemotron-3_5-Lightning" in errors[0].suggestions
    assert (
        _metric_value(provider="nebius", model="nvidia/nemotron-4-340b-instruct", route="reasoning")
        == 0.0
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["http_401", "timeout", "invalid_json"])
async def test_listing_error_logs_warning_and_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
    httpx_mock: HTTPXMock,
    caplog: pytest.LogCaptureFixture,
    case: str,
) -> None:
    reasoning = f"nvidia/reasoning-model-{case}"
    fast = f"nvidia/fast-model-{case}"
    monkeypatch.setattr(settings, "llm_model_reasoning", reasoning)
    monkeypatch.setattr(settings, "llm_model_fast", fast)

    if case == "http_401":
        httpx_mock.add_response(url="https://api.openai.com/v1/models", status_code=401)
    elif case == "timeout":
        httpx_mock.add_exception(
            httpx.ReadTimeout(
                "timed out", request=httpx.Request("GET", "https://api.openai.com/v1/models")
            )
        )
    else:
        httpx_mock.add_response(
            url="https://api.openai.com/v1/models",
            status_code=200,
            text=json.dumps({"unexpected": []}),
        )

    with caplog.at_level("WARNING", logger=LOGGER):
        await preflight_configured_models(
            provider_name="openai",
            api_key="test-token",
            base_url="https://api.openai.com/v1",
        )

    warnings = [r for r in caplog.records if "LLM model preflight failed" in r.getMessage()]
    assert len(warnings) == 1
    assert metrics.sample(METRIC, {"provider": "openai", "model": reasoning, "route": "reasoning"}) is None
    assert metrics.sample(METRIC, {"provider": "openai", "model": fast, "route": "fast"}) is None


@pytest.mark.asyncio
async def test_preflight_skipped_for_ollama_anthropic_and_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preflight = AsyncMock()
    monkeypatch.setattr(api_module, "preflight_configured_models", preflight)
    monkeypatch.setattr(settings, "openai_api_key", "test-token")
    monkeypatch.setattr(settings, "nebius_api_key", "test-token")

    for provider in ("ollama", "anthropic", "none"):
        monkeypatch.setattr(settings, "llm_provider", provider)
        await api_module._run_llm_model_preflight()

    preflight.assert_not_awaited()


@pytest.mark.asyncio
async def test_startup_completes_when_preflight_times_out(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def _slow_preflight(**kwargs) -> None:
        await asyncio.sleep(0.05)

    monkeypatch.setattr(api_module, "preflight_configured_models", _slow_preflight)
    monkeypatch.setattr(api_module, "_LLM_MODEL_PREFLIGHT_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(settings, "llm_provider", "openai")
    monkeypatch.setattr(settings, "openai_api_key", "test-token")
    monkeypatch.setattr(settings, "openai_base_url", "https://api.openai.com/v1")
    monkeypatch.setattr(api_module, "configure_logging", lambda: None)
    monkeypatch.setattr(api_module, "log_auth_status", lambda: None)
    monkeypatch.setattr(api_module.metrics, "set_build_info", lambda _version: None)
    monkeypatch.setattr(api_module, "create_db_and_tables", AsyncMock())
    monkeypatch.setattr(api_module, "mark_interrupted_runs", AsyncMock(return_value=0))
    monkeypatch.setattr(
        api_module,
        "requeue_interrupted_deliveries",
        AsyncMock(return_value={"alert_deliveries": 0, "opencti_outbox": 0}),
    )
    monkeypatch.setattr(api_module, "start_scheduler", lambda: None)
    monkeypatch.setattr(api_module, "shutdown_scheduler", lambda: None)

    with caplog.at_level("WARNING", logger="orchestrator.api"):
        async with api_module.lifespan(api_module.app):
            pass

    assert any("LLM model preflight timed out" in r.getMessage() for r in caplog.records)
