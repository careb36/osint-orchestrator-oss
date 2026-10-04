from __future__ import annotations

from types import SimpleNamespace

import pytest

import orchestrator.synthesizer.providers.openai_compat as openai_compat_module
from orchestrator import metrics
from orchestrator.config import NEBIUS_DEFAULT_BASE_URL, settings
from orchestrator.models import Target
from orchestrator.synthesizer.model_routing import resolve_model_for_route
from orchestrator.synthesizer.providers import LLMClient, get_client
from orchestrator.synthesizer.providers.anthropic import AnthropicClient
from orchestrator.synthesizer.providers.ollama import OllamaClient
from orchestrator.synthesizer.providers.openai_compat import OpenAICompatClient

REQ_METRIC = "osint_orchestrator_llm_requests_total"
TOK_METRIC = "osint_orchestrator_llm_tokens_total"


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
        def __init__(
            self,
            status_code: int,
            message: str = "error",
            *,
            headers: dict | None = None,
            body: dict | None = None,
        ) -> None:
            super().__init__(message)
            self.status_code = status_code
            self.response = SimpleNamespace(headers=headers or {})
            self.body = body

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


@pytest.fixture
def _sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record backoff waits instead of sleeping."""
    recorded: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(openai_compat_module.asyncio, "sleep", _fake_sleep)
    return recorded


def _client() -> OpenAICompatClient:
    return OpenAICompatClient(provider_name="nebius", api_key="test-token", base_url="https://x")


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
    labels = {"provider": "nebius", "model": "nvidia/nemotron-test"}
    before_429 = _metric_value(REQ_METRIC, status="http_429", **labels)
    before_ok = _metric_value(REQ_METRIC, status="ok", **labels)
    before_in = _metric_value(TOK_METRIC, direction="input", **labels)
    before_out = _metric_value(TOK_METRIC, direction="output", **labels)

    await _client().complete("sys", "user", timeout=5)

    assert len(state["payloads"]) == 2
    assert _metric_value(REQ_METRIC, status="http_429", **labels) - before_429 == 1
    assert _metric_value(REQ_METRIC, status="ok", **labels) - before_ok == 1
    assert _metric_value(TOK_METRIC, direction="input", **labels) - before_in == 13
    assert _metric_value(TOK_METRIC, direction="output", **labels) - before_out == 7


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


@pytest.mark.asyncio
async def test_schema_downgrade_does_not_consume_an_attempt(
    monkeypatch: pytest.MonkeyPatch, _sleeps: list[float]
) -> None:
    monkeypatch.setattr(settings, "llm_model", "nvidia/nemotron-test")
    actions: list[object] = []
    fake_sdk, state = _install_fake_openai(monkeypatch, actions)
    actions.extend(
        [
            fake_sdk.APIStatusError(400, "Unrecognized request argument supplied: json_schema"),
            fake_sdk.APIStatusError(503, "upstream"),
            fake_sdk.APIStatusError(503, "upstream"),
            _fake_response(),
        ]
    )
    labels = {"provider": "nebius", "model": "nvidia/nemotron-test"}
    before_probe = _metric_value(REQ_METRIC, status="schema_downgrade", **labels)
    before_error = _metric_value(REQ_METRIC, status="error", **labels)

    await _client().complete("sys", "user", timeout=5, response_schema={"type": "object"})

    # probe + three real attempts: the downgrade did not eat one of the three
    assert len(state["payloads"]) == 4
    assert "response_format" in state["payloads"][0]
    assert all("response_format" not in p for p in state["payloads"][1:])
    assert _metric_value(REQ_METRIC, status="schema_downgrade", **labels) - before_probe == 1
    assert _metric_value(REQ_METRIC, status="error", **labels) - before_error == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "message"),
    [
        (400, "Unrecognized request argument supplied: json_schema"),
        (422, "response_format is not supported by this model"),
        (400, "Invalid value for 'response_format'"),
    ],
)
async def test_schema_rejections_are_detected_across_wordings(
    monkeypatch: pytest.MonkeyPatch, status_code: int, message: str
) -> None:
    actions: list[object] = []
    fake_sdk, state = _install_fake_openai(monkeypatch, actions)
    actions.extend([fake_sdk.APIStatusError(status_code, message), _fake_response()])

    await _client().complete("sys", "user", timeout=5, response_schema={"type": "object"})

    assert len(state["payloads"]) == 2
    assert "response_format" not in state["payloads"][1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [
        "messages[0].content is required",
        # echoes the request body (mentions response_format) but complains about something else
        'max_tokens is too large for this model. request: {"response_format": {"type": "json_schema"}}',
        "model not found. supported parameters: messages, response_format, temperature",
    ],
)
async def test_unrelated_400_is_not_a_downgrade_and_not_retried(
    monkeypatch: pytest.MonkeyPatch, message: str
) -> None:
    actions: list[object] = []
    fake_sdk, state = _install_fake_openai(monkeypatch, actions)
    actions.append(fake_sdk.APIStatusError(400, message))

    with pytest.raises(fake_sdk.APIStatusError):
        await _client().complete("sys", "user", timeout=5, response_schema={"type": "object"})

    assert len(state["payloads"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [408, 409, 500, 507, 599])
async def test_transient_statuses_are_retried(
    monkeypatch: pytest.MonkeyPatch, status_code: int, _sleeps: list[float]
) -> None:
    actions: list[object] = []
    fake_sdk, state = _install_fake_openai(monkeypatch, actions)
    actions.extend([fake_sdk.APIStatusError(status_code, "transient"), _fake_response("x")])

    assert await _client().complete("sys", "user", timeout=5) == "x"
    assert len(state["payloads"]) == 2


@pytest.mark.asyncio
async def test_retry_after_header_sets_the_backoff(
    monkeypatch: pytest.MonkeyPatch, _sleeps: list[float]
) -> None:
    actions: list[object] = []
    fake_sdk, _ = _install_fake_openai(monkeypatch, actions)
    actions.extend(
        [
            fake_sdk.RateLimitError(429, "slow down", headers={"retry-after": "7"}),
            fake_sdk.RateLimitError(429, "slow down", headers={"retry-after": "Thu, 01 Jan"}),
            _fake_response(),
        ]
    )

    await _client().complete("sys", "user", timeout=60)

    assert _sleeps == [7.0, 0.0]  # numeric header honoured; HTTP-date falls back to backoff


@pytest.mark.asyncio
async def test_retries_stop_when_the_wait_would_exceed_the_budget(
    monkeypatch: pytest.MonkeyPatch, _sleeps: list[float]
) -> None:
    actions: list[object] = []
    fake_sdk, state = _install_fake_openai(monkeypatch, actions)
    actions.extend([fake_sdk.RateLimitError(429, "slow", headers={"retry-after": "30"})] * 3)

    with pytest.raises(fake_sdk.RateLimitError):
        await _client().complete("sys", "user", timeout=10)

    assert len(state["payloads"]) == 1  # a 30 s wait does not fit a 10 s budget
    assert _sleeps == []


@pytest.mark.asyncio
async def test_each_attempt_gets_the_remaining_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    actions: list[object] = []
    fake_sdk, state = _install_fake_openai(monkeypatch, actions)
    actions.extend([fake_sdk.APIStatusError(503, "x"), _fake_response()])

    await _client().complete("sys", "user", timeout=5)

    assert state["clients"][0].kwargs["max_retries"] == 0
    assert 0 < state["payloads"][1]["timeout"] <= state["payloads"][0]["timeout"] <= 5


def test_blank_base_url_falls_back_per_preset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "openai_base_url", "")
    assert OpenAICompatClient(api_key="k", base_url="")._base_url is None
    monkeypatch.setattr(settings, "openai_base_url", "https://proxy.example/v1")
    assert OpenAICompatClient(api_key="k", base_url="")._base_url == "https://proxy.example/v1"
    # a named preset never falls away from its own endpoint
    nebius = OpenAICompatClient(provider_name="nebius", api_key="k", base_url=" ")
    assert nebius._base_url == NEBIUS_DEFAULT_BASE_URL
    assert nebius.provider == "nebius"
    with pytest.raises(ValueError, match="needs an explicit base_url"):
        OpenAICompatClient(provider_name="custom", api_key="k", base_url="")


def test_blank_nebius_base_url_uses_the_nebius_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_provider", "nebius")
    monkeypatch.setattr(settings, "nebius_api_key", "test-token")
    monkeypatch.setattr(settings, "nebius_base_url", "")
    client = get_client(_target(llm="openai"))
    assert isinstance(client, OpenAICompatClient)
    assert client._base_url == NEBIUS_DEFAULT_BASE_URL


def test_clients_report_the_model_they_send(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_model", "cloud-model")
    monkeypatch.setattr(settings, "llm_model_reasoning", "reasoning-model")
    monkeypatch.setattr(settings, "ollama_model", "llama3.2")
    assert OpenAICompatClient(api_key="k").model_for_route("reasoning") == "reasoning-model"
    assert AnthropicClient().model_for_route("reasoning") == "reasoning-model"
    assert AnthropicClient().model_for_route("fast") == "cloud-model"
    assert OllamaClient().model_for_route("reasoning") == "llama3.2"
    for client in (OpenAICompatClient(api_key="k"), AnthropicClient(), OllamaClient()):
        assert isinstance(client, LLMClient)


def test_unknown_route_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown model route"):
        resolve_model_for_route("bogus")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_error_param_decides_the_downgrade_when_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actions: list[object] = []
    fake_sdk, state = _install_fake_openai(monkeypatch, actions)
    # The message mentions response_format but the structured param blames another field.
    actions.append(
        fake_sdk.APIStatusError(
            400,
            "invalid request: see response_format docs",
            body={"error": {"param": "max_tokens", "message": "too large"}},
        )
    )
    with pytest.raises(fake_sdk.APIStatusError):
        await _client().complete("sys", "user", timeout=5, response_schema={"type": "object"})
    assert len(state["payloads"]) == 1

    actions.extend(
        [
            fake_sdk.APIStatusError(
                400, "bad request", body={"error": {"param": "response_format.json_schema"}}
            ),
            _fake_response(),
        ]
    )
    await _client().complete("sys", "user", timeout=5, response_schema={"type": "object"})
    assert "response_format" not in state["payloads"][-1]


@pytest.mark.asyncio
async def test_exhausted_budget_raises_the_last_error_instead_of_a_doomed_request(
    monkeypatch: pytest.MonkeyPatch, _sleeps: list[float]
) -> None:
    actions: list[object] = []
    fake_sdk, state = _install_fake_openai(monkeypatch, actions)
    clock = {"now": 100.0}
    monkeypatch.setattr(openai_compat_module.time, "monotonic", lambda: clock["now"])

    async def _slow_503(**payload):
        state["payloads"].append(payload)
        clock["now"] += 10.0  # the failure itself took the whole budget
        raise fake_sdk.APIStatusError(503, "upstream")

    monkeypatch.setattr(
        fake_sdk.AsyncOpenAI, "_create", lambda self, **payload: _slow_503(**payload)
    )

    with pytest.raises(fake_sdk.APIStatusError, match="upstream"):
        await _client().complete("sys", "user", timeout=5)

    assert len(state["payloads"]) == 1  # no 1 ms request was started
    assert _sleeps == []


@pytest.mark.asyncio
async def test_anthropic_records_requests_and_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    import orchestrator.synthesizer.providers.anthropic as anthropic_module

    monkeypatch.setattr(settings, "llm_model", "claude-test")
    monkeypatch.setattr(settings, "llm_model_reasoning", "")
    monkeypatch.setattr(settings, "anthropic_api_key", "test-token")
    calls: list[dict] = []

    class _RateLimitError(Exception):
        status_code = 429

    class _AsyncAnthropic:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs
            self.messages = SimpleNamespace(create=self._create)

        async def _create(self, **kwargs):
            calls.append(kwargs)
            if len(calls) == 2:
                raise _RateLimitError("rate limited")
            return SimpleNamespace(
                content=[SimpleNamespace(text="{}")],
                usage=SimpleNamespace(input_tokens=21, output_tokens=5),
            )

    monkeypatch.setattr(anthropic_module, "_HAS_ANTHROPIC", True)
    monkeypatch.setattr(
        anthropic_module, "_anthropic_sdk", SimpleNamespace(AsyncAnthropic=_AsyncAnthropic)
    )
    labels = {"provider": "anthropic", "model": "claude-test"}
    before_ok = _metric_value(REQ_METRIC, status="ok", **labels)
    before_429 = _metric_value(REQ_METRIC, status="http_429", **labels)
    before_in = _metric_value(TOK_METRIC, direction="input", **labels)

    assert await AnthropicClient().complete("sys", "user", timeout=5) == "{}"
    with pytest.raises(_RateLimitError):
        await AnthropicClient().complete("sys", "user", timeout=5)

    assert calls[0]["model"] == "claude-test"
    assert _metric_value(REQ_METRIC, status="ok", **labels) - before_ok == 1
    assert _metric_value(REQ_METRIC, status="http_429", **labels) - before_429 == 1
    assert _metric_value(TOK_METRIC, direction="input", **labels) - before_in == 21


@pytest.mark.asyncio
async def test_retry_log_carries_attempt_in_extra(
    monkeypatch: pytest.MonkeyPatch, caplog, _sleeps: list[float]
) -> None:
    actions: list[object] = []
    fake_sdk, _ = _install_fake_openai(monkeypatch, actions)
    actions.extend([fake_sdk.APIStatusError(503, "x"), _fake_response()])
    with caplog.at_level("WARNING", logger="orchestrator.synthesizer.providers.openai_compat"):
        await _client().complete("sys", "user", timeout=5)
    failed = next(r for r in caplog.records if "LLM request failed" in r.getMessage())
    assert failed.attempt == 1 and failed.max_attempts == 3 and failed.provider == "nebius"


@pytest.mark.asyncio
async def test_slow_schema_probe_exhausting_the_budget_is_a_timeout(
    monkeypatch: pytest.MonkeyPatch, _sleeps: list[float]
) -> None:
    actions: list[object] = []
    fake_sdk, state = _install_fake_openai(monkeypatch, actions)
    clock = {"now": 100.0}
    monkeypatch.setattr(openai_compat_module.time, "monotonic", lambda: clock["now"])

    async def _slow_rejection(**payload):
        state["payloads"].append(payload)
        clock["now"] += 10.0
        raise fake_sdk.APIStatusError(400, "response_format is not supported")

    monkeypatch.setattr(
        fake_sdk.AsyncOpenAI, "_create", lambda self, **payload: _slow_rejection(**payload)
    )
    labels = {"provider": "nebius", "model": settings.llm_model}
    before_timeout = _metric_value(REQ_METRIC, status="timeout", **labels)

    with pytest.raises(TimeoutError, match="budget"):
        await _client().complete("sys", "user", timeout=5, response_schema={"type": "object"})

    assert len(state["payloads"]) == 1  # the probe; no downgraded retry without budget
    assert _metric_value(REQ_METRIC, status="timeout", **labels) - before_timeout == 1
