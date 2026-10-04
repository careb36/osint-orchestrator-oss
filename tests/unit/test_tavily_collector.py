"""
Unit tests for the Tavily collector.

All tests are offline: the Tavily HTTP API is mocked with pytest-httpx and the
retry backoff sleeps are patched out.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import httpx
import pytest
from pydantic import ValidationError

from orchestrator.collectors import tavily as tavily_module
from orchestrator.collectors.tavily import (
    TAVILY_SEARCH_URL,
    TavilyCollector,
    is_hostname,
    split_csv,
)
from orchestrator.config import Settings, settings
from orchestrator.models import CollectorConfig, CollectorName, CollectorSet, Target

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _target(language: str | None = None, **tavily_cfg) -> Target:
    target = Target(
        id="t1",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        language=language,
    )
    target.collectors.tavily.enabled = True
    for key, value in tavily_cfg.items():
        setattr(target.collectors.tavily, key, value)
    return target


def _collector(language: str | None = None, **tavily_cfg) -> TavilyCollector:
    return TavilyCollector(_target(language=language, **tavily_cfg))


def _result(url: str, title: str = "Title", content: str = "Snippet", **extra) -> dict:
    return {"url": url, "title": title, "content": content, "score": 0.9, **extra}


@pytest.fixture(autouse=True)
def _api_key(monkeypatch):
    monkeypatch.setattr(settings, "tavily_api_key", "test-token")
    monkeypatch.setattr(settings, "tavily_max_calls_per_run", 3)
    monkeypatch.setattr(settings, "tavily_max_results", 5)


@pytest.fixture(autouse=True)
def _no_sleep():
    async def _instant(_delay):
        return None

    with patch.object(tavily_module.asyncio, "sleep", _instant):
        yield


# ─── Model and settings regressions ───────────────────────────────────────────


def test_shared_collector_timeout_default_is_unchanged() -> None:
    # The tavily block must not redeclare timeout_seconds: the class default is
    # what every collector without an explicit value gets.
    assert CollectorConfig().timeout_seconds == 600
    assert CollectorSet().spiderfoot.timeout_seconds == 600


def test_tavily_disabled_by_default_with_global_timeout() -> None:
    cfg = CollectorSet().tavily
    assert cfg.enabled is False
    assert cfg.timeout_seconds == settings.tavily_timeout_seconds
    assert cfg.max_results == 5
    assert cfg.max_calls_per_run == 3


@pytest.mark.parametrize("field", ["max_results", "max_calls_per_run"])
@pytest.mark.parametrize("value", [0, 3000])
def test_tavily_caps_are_bounded(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        CollectorConfig(**{field: value})


@pytest.mark.parametrize(
    "raw",
    ["", "example.com,news.example.com", " example.com , news.example.com ,"],
)
def test_domain_settings_accept_documented_values(monkeypatch, raw: str) -> None:
    monkeypatch.setenv("TAVILY_INCLUDE_DOMAINS", raw)
    monkeypatch.setenv("TAVILY_EXCLUDE_DOMAINS", raw)
    built = Settings()
    assert split_csv(built.tavily_include_domains) == split_csv(raw)


def test_split_csv() -> None:
    assert split_csv("") == []
    assert split_csv(" a.com, b.com ,, ") == ["a.com", "b.com"]
    assert split_csv(["a.com", " b.com "]) == ["a.com", "b.com"]


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("example.com", True),
        ("Sub.Example.COM.", True),
        ("John.Doe", True),
        ("John Doe", False),
        ("localhost", False),
        ("", False),
        ("exa mple.com", False),
        ("-bad.example.com", False),
    ],
)
def test_is_hostname(name: str, ok: bool) -> None:
    assert is_hostname(name) is ok


# ─── Guards (no request leaves the process) ───────────────────────────────────


async def test_disabled_block_is_reported_first(httpx_mock, monkeypatch) -> None:
    monkeypatch.setattr(settings, "tavily_api_key", "")
    collector = _collector()
    collector.target.collectors.tavily.enabled = False
    result = await collector.collect()
    assert result.success is False
    assert result.error == "Tavily: collector disabled"
    assert httpx_mock.get_requests() == []


async def test_missing_api_key_fails_without_requests(httpx_mock, monkeypatch) -> None:
    monkeypatch.setattr(settings, "tavily_api_key", "")
    result = await _collector().collect()
    assert result.success is False
    assert "API key" in result.error
    assert httpx_mock.get_requests() == []


async def test_non_hostname_target_is_rejected(httpx_mock) -> None:
    target = _target()
    target.fqdn = "John Doe"
    result = await TavilyCollector(target).collect()
    assert result.success is False
    assert result.error == "Tavily: target must be a domain name"
    assert httpx_mock.get_requests() == []


# ─── Query building ───────────────────────────────────────────────────────────


def test_queries_follow_target_language_then_global(monkeypatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_language", "es")
    assert all(
        "noticias adversas" in q or "site:" in q for q in _collector().build_queries("example.com")
    )
    assert _collector().build_queries("example.com")[0].startswith("site:example.com noticias")
    assert (
        _collector(language="en")
        .build_queries("example.com")[0]
        .startswith("site:example.com adverse")
    )
    monkeypatch.setattr(settings, "orchestrator_language", "en")
    assert _collector().build_queries("example.com")[0].startswith("site:example.com adverse")


def test_default_call_budget_covers_every_template() -> None:
    queries = _collector(language="en").build_queries("example.com")
    assert len(queries) == CollectorSet().tavily.max_calls_per_run == 3


# ─── Happy path ───────────────────────────────────────────────────────────────


async def test_collect_builds_url_observables_and_stable_notes(httpx_mock) -> None:
    httpx_mock.add_response(
        method="POST",
        url=TAVILY_SEARCH_URL,
        json={
            "results": [
                _result("https://news.example.com/a", title="A", published_date="2026-01-01"),
                _result("https://news.example.com/a", title="A duplicate"),
                _result("javascript:alert(1)", title="evil"),
                _result("ftp://files.example.com/x", title="ftp"),
                _result("", title="no url"),
            ]
        },
    )
    httpx_mock.add_response(
        method="POST",
        url=TAVILY_SEARCH_URL,
        json={"results": [_result("http://other.example.org/b", title="B")]},
    )
    httpx_mock.add_response(method="POST", url=TAVILY_SEARCH_URL, json={"results": []})

    result = await _collector(language="en").collect()

    assert result.success is True
    assert result.collector == CollectorName.TAVILY
    assert [o.value for o in result.observables] == [
        "https://news.example.com/a",
        "http://other.example.org/b",
    ]
    assert all(o.type == "url" and o.extra == {"source": "tavily"} for o in result.observables)
    assert len(result.notes) == 3  # two accepted results, "A duplicate" shares the URL
    note_a = result.notes[0]
    assert note_a.startswith("tavily | A | url=https://news.example.com/a | published=2026-01-01")
    assert "score=" not in note_a and "sha256=" not in note_a
    assert len(httpx_mock.get_requests()) == 3
    payload = json.loads(httpx_mock.get_requests()[0].read())
    assert payload["include_raw_content"] is False
    assert payload["max_results"] == 5
    assert httpx_mock.get_requests()[0].headers["Authorization"] == "Bearer test-token"


async def test_no_results_adds_explanatory_note(httpx_mock) -> None:
    for _ in range(3):
        httpx_mock.add_response(method="POST", url=TAVILY_SEARCH_URL, json={"results": []})
    result = await _collector().collect()
    assert result.success is True
    assert result.observables == []
    assert result.notes == ["tavily: no public results matched the query set"]


async def test_include_answer_is_surfaced_as_bounded_note(httpx_mock) -> None:
    httpx_mock.add_response(
        method="POST",
        url=TAVILY_SEARCH_URL,
        json={"answer": "Line one\nLine `two` " + "x" * 600, "results": []},
    )
    result = await _collector(max_calls_per_run=1, include_answer=True).collect()
    answer_notes = [n for n in result.notes if n.startswith("tavily | answer |")]
    assert len(answer_notes) == 1
    assert "\n" not in answer_notes[0] and "`" not in answer_notes[0]
    assert len(answer_notes[0].rsplit(" | ", 1)[1]) == 500
    assert json.loads(httpx_mock.get_requests()[0].read())["include_answer"] is True


# ─── Budgets ──────────────────────────────────────────────────────────────────


async def test_global_call_cap_clamps_per_target_value(httpx_mock, monkeypatch) -> None:
    monkeypatch.setattr(settings, "tavily_max_calls_per_run", 1)
    httpx_mock.add_response(method="POST", url=TAVILY_SEARCH_URL, json={"results": []})
    await _collector(max_calls_per_run=20).collect()
    assert len(httpx_mock.get_requests()) == 1


async def test_global_max_results_clamps_request_and_kept_results(httpx_mock, monkeypatch) -> None:
    monkeypatch.setattr(settings, "tavily_max_results", 2)
    httpx_mock.add_response(
        method="POST",
        url=TAVILY_SEARCH_URL,
        json={"results": [_result(f"https://example.com/{i}") for i in range(5)]},
    )
    result = await _collector(max_calls_per_run=1, max_results=20).collect()
    assert json.loads(httpx_mock.get_requests()[0].read())["max_results"] == 2
    assert len(result.observables) == 2
    assert len(result.notes) == 2


async def test_domain_lists_fall_back_to_global_settings(httpx_mock, monkeypatch) -> None:
    monkeypatch.setattr(settings, "tavily_include_domains", "a.example.com, b.example.com")
    monkeypatch.setattr(settings, "tavily_exclude_domains", "")
    httpx_mock.add_response(method="POST", url=TAVILY_SEARCH_URL, json={"results": []})
    await _collector(max_calls_per_run=1).collect()
    body = json.loads(httpx_mock.get_requests()[0].read())
    assert body["include_domains"] == ["a.example.com", "b.example.com"]
    assert body["exclude_domains"] == []


async def test_wall_clock_budget_bounds_the_whole_run() -> None:
    collector = _collector(timeout_seconds=1)

    async def _never_returns(*_args, **_kwargs):
        await asyncio.get_running_loop().create_future()

    with patch.object(TavilyCollector, "_search", _never_returns):
        result = await asyncio.wait_for(collector.collect(), timeout=5)

    assert result.success is False
    assert result.error == "Tavily: timed out after 1s"
    assert result.observables == []


# ─── Retry policy ─────────────────────────────────────────────────────────────


async def test_429_then_success_is_retried(httpx_mock) -> None:
    httpx_mock.add_response(method="POST", url=TAVILY_SEARCH_URL, status_code=429)
    httpx_mock.add_response(
        method="POST", url=TAVILY_SEARCH_URL, json={"results": [_result("https://e.com/1")]}
    )
    result = await _collector(max_calls_per_run=1).collect()
    assert result.success is True
    assert [o.value for o in result.observables] == ["https://e.com/1"]
    assert len(httpx_mock.get_requests()) == 2


async def test_5xx_is_retried_and_eventually_gives_up(httpx_mock) -> None:
    for _ in range(4):
        httpx_mock.add_response(method="POST", url=TAVILY_SEARCH_URL, status_code=503)
    result = await _collector(max_calls_per_run=1).collect()
    assert result.success is True  # the query failed, the run is recorded with no results
    assert result.observables == []
    assert len(httpx_mock.get_requests()) == 4


async def test_non_transient_4xx_is_not_retried(httpx_mock) -> None:
    httpx_mock.add_response(method="POST", url=TAVILY_SEARCH_URL, status_code=401)
    result = await _collector(max_calls_per_run=1).collect()
    assert result.observables == []
    assert len(httpx_mock.get_requests()) == 1


async def test_transport_error_is_retried(httpx_mock) -> None:
    httpx_mock.add_exception(httpx.ConnectError("boom"))
    httpx_mock.add_response(method="POST", url=TAVILY_SEARCH_URL, json={"results": []})
    await _collector(max_calls_per_run=1).collect()
    assert len(httpx_mock.get_requests()) == 2


# ─── Pipeline wiring ──────────────────────────────────────────────────────────


def test_pipeline_registers_tavily_only_when_enabled() -> None:
    from orchestrator.pipeline import _get_collectors  # noqa: PLC0415

    target = _target()
    assert any(isinstance(c, TavilyCollector) for c in _get_collectors(target))
    target.collectors.tavily.enabled = False
    assert not any(isinstance(c, TavilyCollector) for c in _get_collectors(target))
