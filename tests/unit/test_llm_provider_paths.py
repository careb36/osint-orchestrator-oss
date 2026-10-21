"""
Provider factory branches and the OpenAI-compatible client's pure helpers.

The synthesis suites exercise the happy path through a fake client. These
tests pin the decisions around it: which provider a target gets and when it
gets none, which errors are retried, when a 400 means "the server refused
``response_format``", how long to wait before a retry, and how the startup
model preflight resolves its endpoint and key.
"""

from __future__ import annotations

import logging

import httpx
import pytest
from pytest_httpx import HTTPXMock

import orchestrator.synthesizer.providers.anthropic as anthropic_module
import orchestrator.synthesizer.providers.openai_compat as compat
from orchestrator.config import NEBIUS_DEFAULT_BASE_URL, settings
from orchestrator.models import Target
from orchestrator.synthesizer.providers import get_client
from orchestrator.synthesizer.providers._policy import status_label


def _target(llm: str) -> Target:
    return Target(
        id="t1",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        llm=llm,
    )


# ── Factory ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("llm", "global_provider", "key_setting"),
    [
        ("anthropic", "ollama", "anthropic_api_key"),
        ("openai", "ollama", "openai_api_key"),
        ("nebius", "ollama", "nebius_api_key"),
    ],
)
def test_remote_provider_without_a_key_yields_no_client(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    llm: str,
    global_provider: str,
    key_setting: str,
) -> None:
    monkeypatch.setattr(settings, "llm_provider", global_provider)
    monkeypatch.setattr(settings, key_setting, "")

    with caplog.at_level(logging.WARNING, logger="orchestrator.synthesizer.providers"):
        assert get_client(_target(llm)) is None

    assert any(key_setting.upper() in r.message for r in caplog.records)


def test_anthropic_target_with_a_key_gets_the_anthropic_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    monkeypatch.setattr(settings, "anthropic_api_key", "test-key")
    client = get_client(_target("anthropic"))
    assert client is not None and client.provider == "anthropic"


@pytest.mark.parametrize(
    ("global_provider", "expected"), [("ollama", "openai"), ("nebius", "nebius")]
)
def test_openai_target_follows_the_global_openai_family_choice(
    monkeypatch: pytest.MonkeyPatch, global_provider: str, expected: str
) -> None:
    monkeypatch.setattr(settings, "llm_provider", global_provider)
    monkeypatch.setattr(settings, "openai_api_key", "test-key")
    monkeypatch.setattr(settings, "nebius_api_key", "test-key")
    client = get_client(_target("openai"))
    assert client is not None and client.provider == expected


def test_provider_none_disables_every_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_provider", "none")
    monkeypatch.setattr(settings, "anthropic_api_key", "test-key")
    for llm in ("local", "anthropic", "openai", "nebius"):
        assert get_client(_target(llm)) is None


# ── SDK availability ──────────────────────────────────────────────────────────


async def test_openai_client_reports_a_missing_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compat, "_HAS_OPENAI", False)
    client = compat.OpenAICompatClient(api_key="test-key", base_url="http://llm.test/v1")
    with pytest.raises(RuntimeError, match="pip install openai"):
        await client.complete("s", "u", timeout=1.0)


async def test_anthropic_client_reports_a_missing_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(anthropic_module, "_HAS_ANTHROPIC", False)
    with pytest.raises(RuntimeError, match="pip install anthropic"):
        await anthropic_module.AnthropicClient().complete("s", "u", timeout=1.0)


# ── Retry and schema-rejection policy ─────────────────────────────────────────


class _StatusError(Exception):
    def __init__(self, message: str, status_code: int, body: object = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


@pytest.mark.parametrize(
    ("exc", "retryable"),
    [
        (_StatusError("busy", 503), True),
        (_StatusError("slow down", 429), True),
        (_StatusError("bad request", 400), False),
        (TimeoutError(), True),
        (ValueError("bad payload"), False),
    ],
    ids=["503", "429", "400", "timeout", "other"],
)
def test_retryable_errors(exc: Exception, retryable: bool) -> None:
    assert compat._is_retryable(exc) is retryable


@pytest.mark.parametrize(
    ("exc", "rejects"),
    [
        (_StatusError("response_format is not supported by this model", 500), False),
        (_StatusError("anything", 400, {"error": {"param": "response_format"}}), True),
        (_StatusError("response_format is not supported", 400, {"param": "messages"}), False),
        (_StatusError("Unrecognized request argument supplied: json_schema", 422), True),
        (_StatusError("max_tokens is too large", 400), False),
    ],
    ids=["5xx-never", "param-authoritative", "other-param", "message-heuristic", "unrelated"],
)
def test_schema_rejection_detection(exc: Exception, rejects: bool) -> None:
    assert compat._rejects_json_schema(exc) is rejects


class _Response:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


class _ResponseError(Exception):
    def __init__(self, headers: dict[str, str]) -> None:
        super().__init__("rate limited")
        self.response = _Response(headers)


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (Exception("no response"), None),
        (_ResponseError({}), None),
        (_ResponseError({"retry-after": " 2.5 "}), 2.5),
        (_ResponseError({"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}), None),
        (_ResponseError({"retry-after": "-1"}), None),
    ],
    ids=["no-response", "no-header", "seconds", "http-date", "negative"],
)
def test_retry_after_header(exc: Exception, expected: float | None) -> None:
    assert compat._retry_after_seconds(exc) == expected


def test_backoff_is_jittered_around_an_exponential_capped_delay() -> None:
    for _ in range(50):
        assert 0.75 <= compat._backoff_seconds(0) <= 1.25
        assert 1.5 <= compat._backoff_seconds(1) <= 2.5
        assert 22.5 <= compat._backoff_seconds(10) <= 37.5


@pytest.mark.parametrize(
    ("exc", "label"),
    [
        (_StatusError("x", 429), "http_429"),
        (_StatusError("x", 502), "http_5xx"),
        (TimeoutError(), "timeout"),
        (_StatusError("x", 400), "error"),
    ],
)
def test_status_label_buckets(exc: Exception, label: str) -> None:
    assert status_label(exc) == label


# ── Model preflight ───────────────────────────────────────────────────────────


def test_preflight_key_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "openai_api_key", " openai-test ")
    monkeypatch.setattr(settings, "nebius_api_key", " nebius-test ")
    assert compat._resolve_preflight_api_key("openai", " explicit ") == "explicit"
    assert compat._resolve_preflight_api_key("openai", None) == "openai-test"
    assert compat._resolve_preflight_api_key("nebius", None) == "nebius-test"
    assert compat._resolve_preflight_api_key("custom", None) == ""


def test_preflight_base_url_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "openai_base_url", "")
    assert compat._resolve_preflight_base_url("openai", " http://x.test/v1 ") == "http://x.test/v1"
    assert compat._resolve_preflight_base_url("openai", None) == "https://api.openai.com/v1"
    monkeypatch.setattr(settings, "openai_base_url", "http://gateway.test/v1")
    assert compat._resolve_preflight_base_url("openai", "  ") == "http://gateway.test/v1"
    assert compat._resolve_preflight_base_url("nebius", None) == NEBIUS_DEFAULT_BASE_URL
    assert compat._resolve_preflight_base_url("custom", None) == "https://api.openai.com/v1"


@pytest.mark.parametrize("payload", [[], {"data": "x"}], ids=["not-an-object", "data-not-a-list"])
def test_model_list_payload_must_be_openai_shaped(payload: object) -> None:
    with pytest.raises(ValueError):
        compat._parse_model_ids(payload)


def test_model_list_ignores_entries_without_a_usable_id() -> None:
    payload = {"data": [{"id": " m1 "}, {"id": ""}, {"id": 3}, "m2", {"name": "m3"}]}
    assert compat._parse_model_ids(payload) == ["m1"]


async def test_preflight_lets_an_outer_timeout_through(httpx_mock: HTTPXMock) -> None:
    """The caller's ``asyncio.wait_for`` budget must not be swallowed as a warning."""
    httpx_mock.add_exception(TimeoutError("budget exhausted"))
    with pytest.raises(TimeoutError):
        await compat.preflight_configured_models(
            provider_name="openai", api_key="test-key", base_url="http://llm.test/v1"
        )


async def test_preflight_http_failure_only_warns(
    httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
) -> None:
    httpx_mock.add_exception(httpx.ConnectError("refused"))
    with caplog.at_level(logging.WARNING, logger=compat.__name__):
        await compat.preflight_configured_models(
            provider_name="openai", api_key="test-key", base_url="http://llm.test/v1"
        )
    record = next(r for r in caplog.records if "preflight failed" in r.message)
    assert record.provider == "openai"


# ── Routing table ─────────────────────────────────────────────────────────────

_GLOBALS = ("ollama", "anthropic", "openai", "nebius", "none")
_EXPECTED = {
    # (target.llm, LLM_PROVIDER) -> provider name, or None for no client
    **{(llm, "none"): None for llm in ("local", "anthropic", "openai", "nebius")},
    **{("local", g): "ollama" for g in _GLOBALS if g != "none"},
    **{("anthropic", g): "anthropic" for g in _GLOBALS if g != "none"},
    **{("openai", g): ("nebius" if g == "nebius" else "openai") for g in _GLOBALS if g != "none"},
    **{("nebius", g): "nebius" for g in _GLOBALS if g != "none"},
}


@pytest.mark.parametrize(("llm", "global_provider"), sorted(_EXPECTED), ids=lambda v: str(v))
def test_every_target_llm_and_global_provider_pair_routes_as_documented(
    monkeypatch: pytest.MonkeyPatch, llm: str, global_provider: str
) -> None:
    """The global setting never picks a provider: it only turns synthesis off
    (``none``) or sends ``llm: openai`` to the Nebius preset (``nebius``)."""
    monkeypatch.setattr(settings, "llm_provider", global_provider)
    for key in ("anthropic_api_key", "openai_api_key", "nebius_api_key"):
        monkeypatch.setattr(settings, key, "test-key")

    client = get_client(_target(llm))

    expected = _EXPECTED[(llm, global_provider)]
    assert (client.provider if client is not None else None) == expected


def test_an_llm_value_that_bypassed_validation_fails_closed() -> None:
    """Target.llm is validated, so this cannot come from targets.yaml. If it
    ever happens, no client is built: the prompts are not sent anywhere."""
    target = Target.model_construct(
        id="t1", fqdn="example.com", authorization="self-owned", purpose="test", llm="other"
    )
    with pytest.raises(AssertionError):
        get_client(target)
