"""
Unit tests for the Amass collector.

All tests are offline: the engine health check is mocked with pytest-httpx and
the CLI clients are replaced by fakes at the subprocess boundary. The fixture
tests/fixtures/amass_subs_names_ip.txt reproduces the real ``oam_subs -names
-ip`` line format (``name[ ip1,ip2,...]``).
"""

from __future__ import annotations

import asyncio
import pathlib
from unittest.mock import patch

import httpx
import pytest

from orchestrator.collectors import amass as amass_module
from orchestrator.collectors.amass import (
    AmassCollector,
    AmassError,
    parse_subs_output,
)
from orchestrator.models import CollectorName, CollectorSet, Target

FIXTURE = (
    pathlib.Path(__file__).parent.parent / "fixtures" / "amass_subs_names_ip.txt"
).read_text()

ENGINE = "http://amass:4000"


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _target(**amass_cfg) -> Target:
    target = Target(id="t1", fqdn="example.com", authorization="self-owned", purpose="test")
    target.collectors.amass.enabled = True
    for key, value in amass_cfg.items():
        setattr(target.collectors.amass, key, value)
    return target


def _collector(**amass_cfg) -> AmassCollector:
    return AmassCollector(_target(**amass_cfg))


def _register_healthy(httpx_mock) -> None:
    httpx_mock.add_response(method="GET", url=f"{ENGINE}/api/v1/health", json={"status": "ok"})


class _FakeRun:
    """Stand-in for AmassCollector._run recording every argv it receives."""

    def __init__(self, subs_output: str = FIXTURE, fail_on: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self._subs_output = subs_output
        self._fail_on = fail_on

    async def __call__(self, argv: list[str]) -> str:
        self.calls.append(argv)
        binary = pathlib.Path(argv[0]).name
        if self._fail_on and binary == self._fail_on:
            raise AmassError(f"{binary} exited 1: boom")
        return self._subs_output if binary == "oam_subs" else ""


# ─── Parser ───────────────────────────────────────────────────────────────────


def test_parse_real_subs_format() -> None:
    names, skipped = parse_subs_output(FIXTURE, "example.com")
    assert skipped == 0
    assert list(names) == [
        "www.example.com",
        "mail.example.com",
        "example.com",
        "bare.example.com",
        "api.example.com",
        "_dmarc.example.com",
    ]
    # Mixed v4/v6 list, de-duplicated across the repeated www line.
    assert names["www.example.com"] == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
    assert names["bare.example.com"] == []
    # Upper case and trailing dot normalised.
    assert names["api.example.com"] == ["93.184.216.36"]


def test_parse_skips_garbage_and_out_of_scope_lines() -> None:
    text = "\n".join(
        [
            "",
            "www.example.com 93.184.216.34",
            "not a hostname!! 1.2.3.4",
            "evil.attacker.net 5.6.7.8",  # oam_subs is scoped, but never trust it blindly
            "ok.example.com not-an-ip,10.0.0.1",
            "-bad-.example.com",
        ]
    )
    names, skipped = parse_subs_output(text, "Example.COM.")
    assert names == {"www.example.com": ["93.184.216.34"], "ok.example.com": ["10.0.0.1"]}
    assert skipped == 4


def test_parse_normalises_ipv6_representation() -> None:
    names, _ = parse_subs_output("v6.example.com 2001:DB8:0:0:0:0:0:1", "example.com")
    assert names["v6.example.com"] == ["2001:db8::1"]


# ─── Command lines ────────────────────────────────────────────────────────────


def test_enum_argv_defaults() -> None:
    argv = _collector().enum_argv("enum.log")
    assert argv[:2] == ["oam_enum", "-engine"]
    assert argv[2].startswith("http://")
    assert argv[3:5] == ["-d", "example.com"]
    assert "-dir" in argv
    assert argv[argv.index("-timeout") + 1] == "10"
    assert argv[argv.index("-log") + 1] == "enum.log"
    assert "-silent" in argv and "-nocolor" in argv
    for flag in ("-active", "-brute", "-include", "-exclude"):
        assert flag not in argv


def test_enum_argv_reflects_target_options() -> None:
    argv = _collector(
        active=True,
        brute=True,
        include=["crt.sh", "HackerTarget"],
        exclude=["Shodan"],
        progress_timeout_minutes=3,
    ).enum_argv("enum.log")
    assert "-active" in argv
    assert "-brute" in argv
    assert argv[argv.index("-include") + 1] == "crt.sh,HackerTarget"
    assert argv[argv.index("-exclude") + 1] == "Shodan"
    assert argv[argv.index("-timeout") + 1] == "3"


def test_subs_argv_never_uses_silent() -> None:
    """``-silent`` makes oam_subs discard stdout — the names we need."""
    argv = _collector().subs_argv()
    assert argv[0] == "oam_subs"
    assert argv[1:5] == ["-d", "example.com", "-names", "-ip"]
    assert "-nocolor" in argv
    assert "-silent" not in argv


# ─── collect(): happy path ────────────────────────────────────────────────────


async def test_collect_happy_path(httpx_mock) -> None:
    _register_healthy(httpx_mock)
    fake = _FakeRun()
    collector = _collector()
    with patch.object(collector, "_run", fake):
        result = await collector.collect()

    assert result.success is True
    assert result.error is None
    assert result.collector is CollectorName.AMASS
    assert result.target_fqdn == "example.com"
    # enum then subs, in that order
    assert [pathlib.Path(c[0]).name for c in fake.calls] == ["oam_enum", "oam_subs"]

    domains = {o.value for o in result.observables if o.type == "domain-name"}
    assert domains == {
        "example.com",
        "www.example.com",
        "mail.example.com",
        "bare.example.com",
        "api.example.com",
        "_dmarc.example.com",
    }
    v4 = {o.value for o in result.observables if o.type == "ipv4-addr"}
    v6 = {o.value for o in result.observables if o.type == "ipv6-addr"}
    assert v4 == {"93.184.216.34", "93.184.216.35", "93.184.216.36"}
    assert v6 == {"2606:2800:220:1:248:1893:25c8:1946"}
    # Every observable is unique (root emitted once even though subs lists it).
    keys = [(o.type, o.value) for o in result.observables]
    assert len(keys) == len(set(keys))

    resolves = {
        (r.source_value, r.target_value, r.target_type)
        for r in result.relationships
        if r.relationship_type == "resolves-to"
    }
    assert ("www.example.com", "93.184.216.34", "ipv4-addr") in resolves
    assert ("www.example.com", "2606:2800:220:1:248:1893:25c8:1946", "ipv6-addr") in resolves
    assert ("example.com", "93.184.216.34", "ipv4-addr") in resolves
    related = {
        r.source_value
        for r in result.relationships
        if r.relationship_type == "related-to" and r.target_value == "example.com"
    }
    assert related == domains - {"example.com"}
    assert len(
        {(r.source_value, r.target_value, r.relationship_type) for r in result.relationships}
    ) == len(result.relationships)
    assert result.notes and "passive" in result.notes[0]
    assert "5 names" in result.notes[0]


async def test_collect_note_reports_mode(httpx_mock) -> None:
    _register_healthy(httpx_mock)
    collector = _collector(active=True, brute=True)
    with patch.object(collector, "_run", _FakeRun(subs_output="")):
        result = await collector.collect()
    assert result.success is True
    assert "active+brute" in result.notes[0]
    # Only the root domain when nothing was discovered.
    assert [o.value for o in result.observables] == ["example.com"]


# ─── collect(): failure paths ─────────────────────────────────────────────────


async def test_engine_down_fails_without_running_clients(httpx_mock) -> None:
    httpx_mock.add_exception(httpx.ConnectError("refused"), url=f"{ENGINE}/api/v1/health")
    fake = _FakeRun()
    collector = _collector()
    with patch.object(collector, "_run", fake):
        result = await collector.collect()
    assert result.success is False
    assert "unreachable" in result.error
    assert ENGINE in result.error
    assert fake.calls == []


async def test_engine_unhealthy_status_fails(httpx_mock) -> None:
    httpx_mock.add_response(method="GET", url=f"{ENGINE}/api/v1/health", status_code=503)
    collector = _collector()
    with patch.object(collector, "_run", _FakeRun()):
        result = await collector.collect()
    assert result.success is False
    assert "unreachable" in result.error


async def test_enum_failure_is_reported_with_detail(httpx_mock) -> None:
    _register_healthy(httpx_mock)
    fake = _FakeRun(fail_on="oam_enum")
    collector = _collector()
    with patch.object(collector, "_run", fake):
        result = await collector.collect()
    assert result.success is False
    assert "oam_enum exited 1: boom" in result.error
    # subs never runs after a failed enumeration
    assert [pathlib.Path(c[0]).name for c in fake.calls] == ["oam_enum"]


async def test_subs_failure_is_reported(httpx_mock) -> None:
    _register_healthy(httpx_mock)
    collector = _collector()
    with patch.object(collector, "_run", _FakeRun(fail_on="oam_subs")):
        result = await collector.collect()
    assert result.success is False
    assert "oam_subs exited 1" in result.error


async def test_wall_clock_timeout(httpx_mock) -> None:
    _register_healthy(httpx_mock)
    collector = _collector(timeout_seconds=1)

    async def _hang(argv: list[str]) -> str:
        await asyncio.sleep(30)
        return ""

    with patch.object(collector, "_run", _hang):
        result = await collector.collect()
    assert result.success is False
    assert "timed out after 1s" in result.error
    assert "enum" in result.error


async def test_error_strings_never_leak_url_userinfo(httpx_mock, monkeypatch) -> None:
    monkeypatch.setattr(amass_module.settings, "amass_engine_url", "http://user:secret@amass:4000")
    httpx_mock.add_exception(
        httpx.ConnectError("refused http://user:secret@amass:4000"),
        url="http://user:secret@amass:4000/api/v1/health",
    )
    result = await _collector().collect()
    assert result.success is False
    assert "secret" not in result.error
    assert "http://amass:4000" in result.error


# ─── _run(): real subprocess boundary ─────────────────────────────────────────


async def test_run_reports_missing_binary(monkeypatch) -> None:
    monkeypatch.setattr(amass_module.settings, "amass_subs_bin", "/nonexistent/oam_subs")
    collector = _collector()
    with pytest.raises(AmassError, match="not installed"):
        await collector._run(collector.subs_argv())


async def test_run_returns_stdout_and_raises_with_stderr_tail() -> None:
    collector = _collector()
    out = await collector._run(["sh", "-c", "printf 'a.example.com 1.2.3.4\\n'"])
    assert out == "a.example.com 1.2.3.4\n"
    with pytest.raises(AmassError, match=r"sh exited 3: bad things http://amass:4000"):
        await collector._run(["sh", "-c", "echo 'bad things http://u:p@amass:4000' >&2; exit 3"])


async def test_run_kills_process_on_cancellation() -> None:
    collector = _collector()
    task = asyncio.create_task(collector._run(["sh", "-c", "exec sleep 30"]))
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_enum_failure_appends_log_tail_and_removes_log(
    httpx_mock, monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(amass_module.settings, "amass_data_dir", str(tmp_path))
    _register_healthy(httpx_mock)
    collector = _collector()
    written: list[pathlib.Path] = []

    async def _fail_and_log(argv: list[str]) -> str:
        # oam_enum resolves -log relative to -dir, exactly like this fake.
        log_name = argv[argv.index("-log") + 1]
        assert "/" not in log_name
        path = pathlib.Path(argv[argv.index("-dir") + 1]) / log_name
        path.write_text("engine said: no data sources\n")
        written.append(path)
        raise AmassError("oam_enum exited 1")

    with patch.object(collector, "_run", _fail_and_log):
        result = await collector.collect()
    assert result.success is False
    assert result.error == "oam_enum exited 1 — engine said: no data sources"
    assert written and not written[0].exists()


async def test_enum_log_removed_after_success(httpx_mock, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(amass_module.settings, "amass_data_dir", str(tmp_path))
    _register_healthy(httpx_mock)
    collector = _collector()

    async def _run(argv: list[str]) -> str:
        if pathlib.Path(argv[0]).name == "oam_enum":
            (tmp_path / argv[argv.index("-log") + 1]).write_text("ok\n")
            return ""
        return FIXTURE

    with patch.object(collector, "_run", _run):
        result = await collector.collect()
    assert result.success is True
    assert list(tmp_path.iterdir()) == []


# ─── Config defaults ──────────────────────────────────────────────────────────


def test_collector_set_amass_disabled_by_default() -> None:
    cfg = CollectorSet()
    assert cfg.amass.enabled is False
    assert cfg.amass.active is False
    assert cfg.amass.brute is False
    assert cfg.amass.include == [] and cfg.amass.exclude == []
    assert cfg.amass.progress_timeout_minutes == 10
    assert cfg.amass.timeout_seconds == amass_module.settings.amass_timeout_seconds


def test_progress_timeout_must_be_positive() -> None:
    with pytest.raises(ValueError):
        CollectorSet(amass={"progress_timeout_minutes": 0})


def test_pipeline_registers_amass_only_when_enabled() -> None:
    from orchestrator.pipeline import _get_collectors  # noqa: PLC0415

    target = _target()
    assert any(isinstance(c, AmassCollector) for c in _get_collectors(target))
    target.collectors.amass.enabled = False
    assert not any(isinstance(c, AmassCollector) for c in _get_collectors(target))


def test_health_check_uses_short_timeout() -> None:
    assert amass_module._HEALTH_TIMEOUT_SECONDS <= 30


# ─── Normaliser integration ───────────────────────────────────────────────────


async def test_result_normalises_to_stix_attributed_to_amass(httpx_mock) -> None:
    from orchestrator.normalizer.stix import (  # noqa: PLC0415
        _IDENTITIES,
        _TOOL_CONFIDENCE,
        normalize,
    )

    # Every collector must carry its own identity; otherwise the bundle is
    # silently attributed to OpenOSINT.
    assert set(_IDENTITIES) == set(CollectorName)
    assert set(_TOOL_CONFIDENCE) == set(CollectorName)

    _register_healthy(httpx_mock)
    collector = _collector()
    with patch.object(collector, "_run", _FakeRun()):
        result = await collector.collect()
    bundle = normalize(result)
    by_type: dict[str, int] = {}
    for obj in bundle.objects:
        by_type[obj.type] = by_type.get(obj.type, 0) + 1
    assert by_type["identity"] == 1
    assert next(o for o in bundle.objects if o.type == "identity").name == "OWASP Amass"
    assert by_type["domain-name"] == 6
    assert by_type["ipv4-addr"] == 3
    assert by_type["ipv6-addr"] == 1
    assert by_type["relationship"] == len(result.relationships)
    assert by_type["note"] == 1
