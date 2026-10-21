"""
OpenCTI sink: retry policy, error classification, off-loop execution.

The fake client reproduces pycti's real failure modes (see the sink's module
docstring): ``query()`` raising ``requests`` exceptions or ``ValueError``, and
``import_bundle_from_json()`` returning ``(imported, failed)``.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
import types
from unittest.mock import AsyncMock, MagicMock

import pytest
import requests
import stix2

import orchestrator.sinks as sink_mod
from orchestrator import metrics
from orchestrator.sinks import OpenCTIIngestError, OpenCTISink, backoff_delay, is_transient

PREFIX = metrics.PREFIX


# ── fakes ─────────────────────────────────────────────────────────────────────


class _FakeStix2:
    def __init__(self, outcomes: list[object], block_seconds: float = 0.0) -> None:
        self.outcomes = list(outcomes)
        self.block_seconds = block_seconds
        self.calls = 0

    def import_bundle_from_json(self, bundle_json: str, update: bool = True):
        self.calls += 1
        if self.block_seconds:
            time.sleep(self.block_seconds)
        outcome = self.outcomes.pop(0) if self.outcomes else None
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome if outcome is not None else ([{"id": "x"}], [])


class _FakeClient:
    """``probe`` is consumed one entry per ``query()``: an exception to raise or None."""

    def __init__(self, probe: list[object] | None = None, **stix2_kwargs) -> None:
        self.probe = list(probe or [])
        self.probe_calls = 0
        self.stix2 = _FakeStix2(**stix2_kwargs) if stix2_kwargs else _FakeStix2([])

    def query(self, _query: str):
        self.probe_calls += 1
        if self.probe:
            exc = self.probe.pop(0)
            if exc is not None:
                raise exc
        return {"data": {"me": {"id": "user--1"}}}


@pytest.fixture
def bundle() -> stix2.Bundle:
    return stix2.Bundle(stix2.DomainName(value="example.com"))


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> tuple[AsyncMock, MagicMock]:
    async_sleep, sync_sleep = AsyncMock(), MagicMock()
    monkeypatch.setattr(sink_mod, "_async_sleep", async_sleep)
    monkeypatch.setattr(sink_mod, "_sync_sleep", sync_sleep)
    monkeypatch.setattr(sink_mod.settings, "opencti_ingest_retries", 3)
    monkeypatch.setattr(sink_mod.settings, "opencti_ingest_backoff_seconds", 2.0)
    return async_sleep, sync_sleep


def _sink_with(monkeypatch: pytest.MonkeyPatch, client: object) -> OpenCTISink:
    monkeypatch.setattr(OpenCTISink, "_make_client", lambda self: client)
    return OpenCTISink()


def _retries(target_id: str) -> float:
    return metrics.sample(f"{PREFIX}_opencti_ingest_retries_total", {"target_id": target_id}) or 0.0


# ── retry policy ──────────────────────────────────────────────────────────────


async def test_transient_twice_then_success(monkeypatch, bundle, sleeps, caplog) -> None:
    async_sleep, _ = sleeps
    client = _FakeClient(
        probe=[requests.ConnectionError("refused"), requests.Timeout("slow"), None]
    )
    sink = _sink_with(monkeypatch, client)
    before = _retries("t-ok")

    with caplog.at_level(logging.WARNING, logger="orchestrator.sinks"):
        await sink.ingest_async(bundle, work_name="w", target_id="t-ok")

    assert client.probe_calls == 3
    assert client.stix2.calls == 1, "the import ran exactly once, after the probe recovered"
    assert async_sleep.await_count == 2
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 2
    assert warnings[0].target_id == "t-ok" and warnings[0].attempt == 1
    assert _retries("t-ok") - before == 2


async def test_transient_exhausts_retries_and_raises_last_error(
    monkeypatch, bundle, sleeps
) -> None:
    async_sleep, _ = sleeps
    client = _FakeClient(probe=[requests.ConnectionError(f"down {i}") for i in range(10)])
    sink = _sink_with(monkeypatch, client)
    before = _retries("t-down")

    with pytest.raises(requests.ConnectionError, match="down 3"):
        await sink.ingest_async(bundle, target_id="t-down")

    assert client.probe_calls == 4, "first attempt + 3 retries"
    assert client.stix2.calls == 0
    assert async_sleep.await_count == 3
    assert _retries("t-down") - before == 3


async def test_permanent_error_fails_on_first_attempt(monkeypatch, bundle, sleeps) -> None:
    async_sleep, _ = sleeps
    auth = ValueError({"name": "AUTH_REQUIRED", "error_message": "You must be logged in"})
    client = _FakeClient(probe=[auth])
    sink = _sink_with(monkeypatch, client)
    before = _retries("t-auth")

    with pytest.raises(ValueError, match="AUTH_REQUIRED"):
        await sink.ingest_async(bundle, target_id="t-auth")

    assert client.probe_calls == 1
    assert client.stix2.calls == 0
    assert async_sleep.await_count == 0
    assert _retries("t-auth") - before == 0


async def test_objects_rejected_by_pycti_fail_the_bundle_without_retry(
    monkeypatch, bundle, sleeps
) -> None:
    async_sleep, _ = sleeps
    client = _FakeClient(outcomes=[([{"id": "a"}], [{"id": "b", "rejection_info": {}}])])
    sink = _sink_with(monkeypatch, client)

    with pytest.raises(OpenCTIIngestError, match="1 of 1 objects rejected") as info:
        await sink.ingest_async(bundle, target_id="t-rej")

    assert info.value.transient is False
    assert client.stix2.calls == 1
    assert async_sleep.await_count == 0


async def test_ingest_async_does_not_block_the_event_loop(monkeypatch, bundle, sleeps) -> None:
    client = _FakeClient(outcomes=[], block_seconds=0.3)
    sink = _sink_with(monkeypatch, client)

    task = asyncio.create_task(sink.ingest_async(bundle, target_id="t-thread"))
    started = time.perf_counter()
    await asyncio.sleep(0.02)  # would only resume after 0.3 s if the loop were blocked
    elapsed = time.perf_counter() - started
    await task

    assert elapsed < 0.2, f"event loop was blocked for {elapsed:.3f}s"
    assert client.stix2.calls == 1


async def test_without_pycti_is_a_noop_with_a_warning(monkeypatch, bundle, sleeps, caplog) -> None:
    sink = _sink_with(monkeypatch, None)
    with caplog.at_level(logging.WARNING, logger="orchestrator.sinks"):
        await sink.ingest_async(bundle, target_id="t-none")
    assert any("skipping ingest" in r.getMessage() for r in caplog.records)


async def test_missing_token_is_reported_per_bundle_not_raised_at_construction(
    monkeypatch, bundle, sleeps
) -> None:
    class _Refusing:
        def __init__(self, **_: object) -> None:
            raise ValueError("A TOKEN must be set")

    monkeypatch.setitem(sys.modules, "pycti", types.SimpleNamespace(OpenCTIApiClient=_Refusing))
    sink = OpenCTISink()  # must not raise: the pipeline builds it outside its try/except

    with pytest.raises(OpenCTIIngestError, match="TOKEN must be set") as info:
        await sink.ingest_async(bundle, target_id="t-cfg")
    assert info.value.transient is False


def test_sync_ingest_uses_the_same_policy_with_blocking_waits(monkeypatch, bundle, sleeps) -> None:
    _, sync_sleep = sleeps
    client = _FakeClient(probe=[requests.ConnectionError("refused"), None])
    sink = _sink_with(monkeypatch, client)

    sink.ingest(bundle, "w", target_id="t-sync")

    assert client.probe_calls == 2 and client.stix2.calls == 1
    assert sync_sleep.call_count == 1


# ── classification and backoff ───────────────────────────────────────────────


@pytest.mark.parametrize(
    ("exc", "transient"),
    [
        (requests.ConnectionError("refused"), True),
        (requests.Timeout("slow"), True),
        (requests.exceptions.ProxyError("proxy"), True),
        (ValueError({"name": "LOCK_ERROR", "error_message": "locked"}), True),
        (ValueError({"name": "DATABASE_ERROR"}), True),
        (ValueError({"name": "AUTH_REQUIRED"}), False),
        (ValueError({"name": "FORBIDDEN_ACCESS"}), False),
        (ValueError({"name": "VALIDATION_ERROR"}), False),
        (ValueError({"name": "SOMETHING_NEW"}), False),
        (ValueError("<html><title>502 Bad Gateway</title></html>"), True),
        (ValueError("503 Service Temporarily Unavailable"), True),
        (ValueError("429 Too Many Requests"), True),
        (ValueError("401 Unauthorized"), False),
        (ValueError("JSON data type is not a STIX2 bundle"), False),
        (OpenCTIIngestError("x", transient=True), True),
        (OpenCTIIngestError("x", transient=False), False),
        (RuntimeError("anything else"), False),
    ],
)
def test_is_transient_table(exc: BaseException, transient: bool) -> None:
    assert is_transient(exc) is transient


def test_backoff_doubles_with_bounded_jitter_and_a_cap() -> None:
    for attempt, nominal in [(0, 2.0), (1, 4.0), (2, 8.0), (3, 16.0)]:
        for _ in range(50):
            delay = backoff_delay(attempt, base=2.0)
            assert nominal * 0.75 <= delay <= nominal * 1.25
    for _ in range(50):
        assert backoff_delay(6, base=2.0) <= sink_mod.MAX_BACKOFF_SECONDS  # 128 s nominal


def test_sync_ingest_permanent_error_raises_without_waiting(monkeypatch, bundle, sleeps) -> None:
    """The bundle CLI uses the sync path: a refused token must fail at once."""
    _, sync_sleep = sleeps
    auth = ValueError({"name": "AUTH_REQUIRED", "error_message": "You must be logged in"})
    client = _FakeClient(probe=[auth])
    sink = _sink_with(monkeypatch, client)

    with pytest.raises(ValueError, match="AUTH_REQUIRED"):
        sink.ingest(bundle, "w", target_id="t-sync-auth")

    assert client.probe_calls == 1
    assert sync_sleep.call_count == 0


def test_sync_ingest_without_pycti_is_a_noop(monkeypatch, bundle, sleeps) -> None:
    _, sync_sleep = sleeps
    sink = _sink_with(monkeypatch, None)
    sink.ingest(bundle, "w", target_id="t-sync-none")
    assert sync_sleep.call_count == 0


def test_missing_pycti_package_builds_no_client(monkeypatch, caplog) -> None:
    monkeypatch.setitem(sys.modules, "pycti", None)  # makes ``import pycti`` raise ImportError
    with caplog.at_level(logging.WARNING, logger="orchestrator.sinks"):
        sink = OpenCTISink()
    assert sink._client is None
    assert any("pycti not installed" in r.getMessage() for r in caplog.records)


def test_rejected_summary_names_objects_and_counts_the_overflow() -> None:
    failed = [{"id": f"domain-name--{i}", "type": "domain-name"} for i in range(11)]
    failed.insert(1, {"standard_id": "ipv4-addr--1", "entity_type": "IPv4-Addr"})
    failed.insert(2, "x" * 200)

    summary = sink_mod._rejected_summary(failed)

    assert summary.startswith("domain-name--0 (domain-name), ipv4-addr--1 (IPv4-Addr), " + "x" * 80)
    assert summary.endswith(" (+3 more)")
