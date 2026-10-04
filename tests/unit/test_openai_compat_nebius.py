from __future__ import annotations

from types import SimpleNamespace

import pytest

import orchestrator.synthesizer.providers.openai_compat as openai_compat_module
from orchestrator import metrics
from orchestrator.config import settings
from orchestrator.models import Target
from orchestrator.synthesizer.providers import get_client
from orchestrator.synthesizer.providers.openai_compat import OpenAICompatClient


def _target(*, llm: str = "openai") -> Target:
    return Target(
        id="t-nebius",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        llm=llm,
    )


def _fake_response(
    content: str = '{"summary":"ok","new_since_last_run":[],"risk_level":"low","risk_justification":"","suggested_pivots":[]}',
    *,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
        usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens),
    )


def _install_fake_openai(monkeypatch: pytest.MonkeyPatch, actions: list[object]):
    state: dict[str, list[object]] = {"payloads": [], "clients": []}

    class _APIStatusError(Exception):
        def __init__(self, status_code: int, message: str = "error") -> None:
            super().__init__(message)
            self.status_code = status_code

    class _RateLimitError(_APIStatusError):
        pass

    class _APITimeoutError(Exception):
        pass

    class _APIConnectionError(Exception):
        pass

    class _AsyncOpenAI:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))
            state["clients"].append(self)

        async def _create(self, **payload):
            state["payloads"].append(payload)
            action = actions.pop(0)
            if isinstance(action, Exception):
                raise action
            return action

    fake_sdk = SimpleNamespace(
        AsyncOpenAI=_AsyncOpenAI,
        APIStatusError=_APIStatusError,
        RateLimitError=_RateLimitError,
        APITimeoutError=_APITimeoutError,
        APIConnectionError=_APIConnectionError,
    )
    monkeypatch.setattr(openai_compat_module, "_HAS_OPENAI", True)
    monkeypatch.setattr(openai_compat_module, "_openai_sdk", fake_sdk)
    monkeypatch.setattr(openai_compat_module, "_backoff_seconds", lambda _idx: 0.0)
    return fake_sdk, state


def _metric_value(name: str, **labels: str) -> float:
    return metrics.sample(name, labels) or 0.0


def test_nebius_provider_preset_uses_openai_compat_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_provider", "nebius")
    monkeypatch.setattr(settings, "nebius_api_key", "test-token")
    monkeypatch.setattr(settings, "nebius_base_url", "https://api.tokenfactory.nebius.com/v1")

    client = get_client(_target(llm="openai"))

    assert isinstance(client, OpenAICompatClient)
    assert client._provider_name == "nebius"
    assert client._api_key == "test-token"
    assert client._base_url == "https://api.tokenfactory.nebius.com/v1"


def test_nebius_provider_without_key_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_provider", "nebius")
    monkeypatch.setattr(settings, "nebius_api_key", "")
    assert get_client(_target(llm="openai")) is None


@pytest.mark.asyncio
async def test_openai_compat_routes_reasoning_and_fast_models(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_model", "fallback-model")
    monkeypatch.setattr(settings, "llm_model_reasoning", "reasoning-model")
    monkeypatch.setattr(settings, "llm_model_fast", "fast-model")
    _, state = _install_fake_openai(monkeypatch, [_fake_response(), _fake_response()])

    client = OpenAICompatClient(provider_name="nebius", api_key="test-token", base_url="https://x")
    await client.complete("sys", "user", timeout=5, model_route="reasoning")
    await client.complete("sys", "user", timeout=5, model_route="fast")

    assert state["payloads"][0]["model"] == "reasoning-model"
    assert state["payloads"][1]["model"] == "fast-model"


@pytest.mark.asyncio
async def test_openai_compat_fast_route_falls_back_to_llm_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_model", "fallback-model")
    monkeypatch.setattr(settings, "llm_model_fast", "")
    _, state = _install_fake_openai(monkeypatch, [_fake_response()])

    client = OpenAICompatClient(provider_name="nebius", api_key="test-token", base_url="https://x")
    await client.complete("sys", "user", timeout=5, model_route="fast")

    assert state["payloads"][0]["model"] == "fallback-model"


@pytest.mark.asyncio
async def test_openai_compat_retries_429_and_tracks_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_model", "nvidia/nemotron-test")
    monkeypatch.setattr(settings, "llm_model_reasoning", "")
    monkeypatch.setattr(settings, "llm_model_fast", "")
    actions: list[object] = []
    fake_sdk, state = _install_fake_openai(monkeypatch, actions)
    actions.extend(
        [
            fake_sdk.RateLimitError(429, "rate limited"),
            _fake_response(prompt_tokens=13, completion_tokens=7),
        ]
    )
    model = "nvidia/nemotron-test"
    req_metric = "osint_orchestrator_llm_requests_total"
    tok_metric = "osint_orchestrator_llm_tokens_total"
    before_429 = _metric_value(req_metric, model=model, status="http_429")
    before_ok = _metric_value(req_metric, model=model, status="ok")
    before_in = _metric_value(tok_metric, model=model, direction="input")
    before_out = _metric_value(tok_metric, model=model, direction="output")

    client = OpenAICompatClient(provider_name="nebius", api_key="test-token", base_url="https://x")
    await client.complete("sys", "user", timeout=5)

    assert len(state["payloads"]) == 2
    assert _metric_value(req_metric, model=model, status="http_429") - before_429 == 1
    assert _metric_value(req_metric, model=model, status="ok") - before_ok == 1
    assert _metric_value(tok_metric, model=model, direction="input") - before_in == 13
    assert _metric_value(tok_metric, model=model, direction="output") - before_out == 7


@pytest.mark.asyncio
async def test_openai_compat_downgrades_when_json_schema_not_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_model", "nvidia/nemotron-test")
    actions: list[object] = []
    fake_sdk, state = _install_fake_openai(monkeypatch, actions)
    actions.extend(
        [
            fake_sdk.APIStatusError(400, "response_format json_schema unsupported"),
            _fake_response(),
        ]
    )

    client = OpenAICompatClient(provider_name="nebius", api_key="test-token", base_url="https://x")
    await client.complete(
        "sys",
        "user",
        timeout=5,
        response_schema={"type": "object", "properties": {"summary": {"type": "string"}}},
    )

    assert "response_format" in state["payloads"][0]
    assert "response_format" not in state["payloads"][1]
