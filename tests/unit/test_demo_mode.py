"""
Public demo mode (issue #18).

API-level tests start the real app through its lifespan against the session's
temporary SQLite database, so the routes, the pipeline and the limits are the
ones production runs. Tavily is mocked with pytest-httpx, which fails a test on
any request it was not told to expect; the OpenCTI sink is replaced by a class
that fails if it is ever constructed.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette.requests import Request

import orchestrator.api as api_module
import orchestrator.demo as demo
import orchestrator.pipeline as pipeline_module
import orchestrator.synthesizer as synth_module
import orchestrator.synthesizer.qualify as qualify_module
from orchestrator.collectors.tavily import TAVILY_SEARCH_URL, TavilyCollector
from orchestrator.config import settings
from orchestrator.evidence import verify_target_chain
from orchestrator.models import EvidenceItem, FindingRecord, Run, RunStatus, Target
from orchestrator.reports import RunReportData

API_KEY = "test-token"
SIGNING_KEY = "test-signing-key"

_TARGETS = """
targets:
  - id: {target_id}
    fqdn: example.com
    authorization: "Public demo on public information."
    purpose: "Demonstration"
    language: en
    report_dir: {report_dir}
    collectors:
      openosint: {{enabled: {openosint}}}
      spiderfoot: {{enabled: false}}
      tavily:
        enabled: true
        search_terms: ["Example Corp"]
        max_calls_per_run: 3
"""


def _write_targets(
    tmp_path: Path, *, target_id: str = "demo-corp", openosint: str = "false"
) -> str:
    path = tmp_path / "targets.demo.yaml"
    path.write_text(
        _TARGETS.format(target_id=target_id, report_dir=tmp_path / "reports", openosint=openosint),
        encoding="utf-8",
    )
    return str(path)


@pytest.fixture
def demo_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A safe demo configuration; tests override single settings from here."""
    monkeypatch.setattr(settings, "demo_mode", True)
    monkeypatch.setattr(settings, "opencti_enabled", False)
    monkeypatch.setattr(settings, "orchestrator_secret_key", SIGNING_KEY)
    monkeypatch.setattr(settings, "orchestrator_api_key", API_KEY)
    monkeypatch.setattr(settings, "demo_targets_file", _write_targets(tmp_path))
    monkeypatch.setattr(settings, "demo_trusted_proxy_hops", 1)
    monkeypatch.setattr(settings, "demo_max_runs_per_ip_per_day", 3)
    monkeypatch.setattr(settings, "demo_max_runs_per_day", 50)
    monkeypatch.setattr(settings, "demo_tavily_calls_per_day", 150)
    monkeypatch.setattr(settings, "demo_llm_calls_per_day", 300)
    monkeypatch.setattr(settings, "llm_provider", "none")
    monkeypatch.setattr(settings, "orchestrator_language", "en")
    monkeypatch.setattr(settings, "tavily_api_key", "test-token")
    monkeypatch.setattr(settings, "tavily_max_calls_per_run", 3)
    return tmp_path


def _db() -> sqlite3.Connection:
    return sqlite3.connect(os.environ["ORCHESTRATOR_DATABASE_URL"].split("///", 1)[1])


@pytest.fixture
def client(demo_settings: Path, monkeypatch: pytest.MonkeyPatch):
    """The real app in demo mode, with a clean slate for the demo target."""

    class _NoOpenCTI:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("the OpenCTI sink must not be used in demo mode")

    monkeypatch.setattr(pipeline_module, "OpenCTISink", _NoOpenCTI)
    api_module._demo_verify_cache.clear()  # module state keyed by target id
    with TestClient(api_module.app) as test_client:
        with _db() as conn:
            conn.execute("DELETE FROM demo_daily_usage")
            conn.execute(
                "DELETE FROM run_observables WHERE run_id IN "
                "(SELECT id FROM runs WHERE target_id = 'demo-corp')"
            )
            for table in ("findings", "evidence_qualifications", "runs"):
                conn.execute(f"DELETE FROM {table} WHERE target_id = 'demo-corp'")  # noqa: S608
            conn.execute("DELETE FROM seen_observables WHERE target_id = 'demo-corp'")
        yield test_client


def _tavily_page(httpx_mock, count: int = 3) -> None:
    for i in range(count):
        httpx_mock.add_response(
            method="POST",
            url=TAVILY_SEARCH_URL,
            json={
                "results": [
                    {"url": f"https://news.example.org/{i}", "title": f"T{i}", "content": "c"}
                ]
            },
        )


def _post_run(client: TestClient, ip: str = "203.0.113.7", target_id: str = "demo-corp"):
    return client.post(f"/demo/targets/{target_id}/run", headers={"X-Forwarded-For": ip})


@asynccontextmanager
async def _memory_db(monkeypatch: pytest.MonkeyPatch, *modules):
    """An in-memory database patched into the given modules' get_session."""
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

    for module in modules:
        monkeypatch.setattr(module, "get_session", _session)
    yield _session
    await engine.dispose()


# ─── Startup ──────────────────────────────────────────────────────────────────


def test_demo_mode_starts_and_mounts_demo_routes(client: TestClient) -> None:
    listing = client.get("/demo/targets")
    assert listing.status_code == 200
    assert listing.json() == [
        {"id": "demo-corp", "fqdn": "example.com", "search_terms": ["Example Corp"]}
    ]
    page = client.get("/demo")
    assert page.status_code == 200
    assert "not an assessment" in page.text  # the disclaimer
    assert client.get("/demo/targets/demo-corp/runs").json() == []


def test_demo_page_language_follows_query_then_accept_language(client: TestClient) -> None:
    # The operator default is "en" here; the visitor's choice wins over it.
    es = client.get("/demo", params={"lang": "es"})
    assert es.status_code == 200
    assert '<html lang="es">' in es.text
    assert "Demostración con información pública" in es.text

    header = client.get("/demo", headers={"Accept-Language": "es-UY,es;q=0.9,en;q=0.8"})
    assert '<html lang="es">' in header.text

    # quality values decide, and q=0 excludes a language
    weighted = client.get("/demo", headers={"Accept-Language": "es;q=0.8,en;q=0.9"})
    assert '<html lang="en">' in weighted.text
    excluded = client.get("/demo", headers={"Accept-Language": "fr,es;q=0,en;q=0.1"})
    assert '<html lang="en">' in excluded.text
    # equal quality: the first listed wins, not the alphabetically smaller tag
    ordered = client.get("/demo", headers={"Accept-Language": "en,es"})
    assert '<html lang="en">' in ordered.text
    ordered_es = client.get("/demo", headers={"Accept-Language": "es;q=0.9,en;q=0.9"})
    assert '<html lang="es">' in ordered_es.text

    unknown = client.get("/demo", params={"lang": "xx"})
    assert '<html lang="en">' in unknown.text  # falls back to the global setting


def test_unsupported_visitor_locale_falls_back_without_a_warning(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    # Visitor input must not become log noise on a public page.
    with caplog.at_level("WARNING", logger="orchestrator.i18n"):
        resp = client.get("/demo", headers={"Accept-Language": "fr-FR,fr;q=0.9"})
    assert resp.status_code == 200 and '<html lang="en">' in resp.text
    assert not [r for r in caplog.records if r.name == "orchestrator.i18n"]


def test_public_chain_verify_counts_errors_like_the_protected_route(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from orchestrator import metrics

    api_module._demo_verify_cache.clear()

    async def _boom(**kwargs):
        raise RuntimeError("disk gone")

    monkeypatch.setattr(api_module, "verify_target_chain", _boom)
    labels = {"target_id": "demo-corp", "outcome": "error"}
    before = metrics.sample("osint_orchestrator_evidence_chain_verify_total", labels) or 0.0
    with pytest.raises(RuntimeError):
        client.get("/demo/targets/demo-corp/chain/verify")
    assert metrics.sample("osint_orchestrator_evidence_chain_verify_total", labels) - before == 1


def test_health_is_ok_in_demo_mode_with_the_sink_off_by_design(client: TestClient) -> None:
    payload = client.get("/health").json()
    assert payload["status"] == "ok"
    assert payload["checks"]["opencti"]["status"] == "disabled"
    assert payload["checks"]["opencti"]["hint"]
    assert payload["checks"]["opencti"]["action"]


def test_demo_routes_are_404_when_demo_mode_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "demo_mode", False)
    with TestClient(api_module.app) as plain:
        assert plain.get("/demo/targets").status_code == 404
        assert plain.get("/demo").status_code == 404
        assert plain.post("/demo/targets/demo-corp/run").status_code == 404


@pytest.mark.parametrize(
    ("setting", "value", "expected"),
    [
        ("opencti_enabled", True, "OPENCTI_ENABLED must be false"),
        ("orchestrator_secret_key", "insecure-dev-key", "ORCHESTRATOR_SECRET_KEY must be set"),
        ("orchestrator_secret_key", "", "ORCHESTRATOR_SECRET_KEY must be set"),
        ("orchestrator_api_key", "", "ORCHESTRATOR_API_KEY must be set"),
        ("demo_max_runs_per_ip_per_day", 0, "DEMO_MAX_RUNS_PER_IP_PER_DAY must be > 0"),
        ("tavily_api_key", "", "TAVILY_API_KEY must be set"),
    ],
)
def test_demo_mode_refuses_to_start_with_opencti_enabled_or_non_tavily_collectors(
    demo_settings: Path, monkeypatch: pytest.MonkeyPatch, setting: str, value: object, expected: str
) -> None:
    demo.validate_demo_mode()  # the baseline configuration is accepted
    monkeypatch.setattr(settings, setting, value)
    with pytest.raises(RuntimeError, match=expected):
        demo.validate_demo_mode()


def test_demo_mode_refuses_a_target_with_another_collector(
    demo_settings: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        settings, "demo_targets_file", _write_targets(demo_settings, openosint="true")
    )
    with pytest.raises(RuntimeError, match="only the tavily collector may be enabled"):
        demo.validate_demo_mode()


def test_scheduler_schedules_nothing_in_demo_mode(demo_settings: Path) -> None:
    from orchestrator import scheduler as scheduler_module  # noqa: PLC0415

    assert scheduler_module._load_targets() == ([], [], False)


# ─── Access ───────────────────────────────────────────────────────────────────


def test_non_allowlisted_target_is_404(client: TestClient) -> None:
    assert _post_run(client, target_id="someone-else").status_code == 404
    assert client.get("/demo/targets/someone-else/chain/verify").status_code == 404
    # A run of a target that is not on the allowlist is invisible to the demo.
    with _db() as conn:
        cursor = conn.execute(
            "INSERT INTO runs (target_id, started_at, status, collectors_run, new_observables) "
            "VALUES ('private-target', '2026-09-08 12:00:00', 'SUCCESS', '', 0)"
        )
        private_run = cursor.lastrowid
    try:
        for suffix in ("", "/evidence", "/finding", "/report", "/manifest"):
            assert client.get(f"/demo/runs/{private_run}{suffix}").status_code == 404
    finally:
        with _db() as conn:
            conn.execute("DELETE FROM runs WHERE id = ?", (private_run,))


def test_protected_routes_still_require_api_key_in_demo_mode(client: TestClient) -> None:
    for path in ("/targets", "/runs", "/analytics/risk-trends"):
        assert client.get(path).status_code == 401
    assert client.post("/targets/demo-corp/run").status_code == 401
    assert client.get("/runs", headers={"X-API-Key": API_KEY}).status_code == 200


# ─── Limits ───────────────────────────────────────────────────────────────────


@pytest.fixture
def no_pipeline(monkeypatch: pytest.MonkeyPatch):
    """Accept runs without executing them, so only the limits are exercised."""
    counter = iter(range(1000, 2000))

    async def _admit(_target_id: str) -> int:
        return next(counter)

    async def _noop(*_args: object) -> None:
        return None

    monkeypatch.setattr(api_module, "create_pending_run", _admit)
    monkeypatch.setattr(api_module, "run_target_pipeline", _noop)


def test_per_ip_limit_returns_429_with_retry_after(
    client: TestClient, no_pipeline: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "demo_max_runs_per_ip_per_day", 2)
    assert _post_run(client).status_code == 202
    assert _post_run(client).status_code == 202
    refused = _post_run(client)
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) > 0
    assert "daily limit" in refused.json()["detail"]
    # Another visitor is not affected.
    assert _post_run(client, ip="198.51.100.9").status_code == 202


def test_global_daily_limit_returns_429(
    client: TestClient, no_pipeline: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "demo_max_runs_per_day", 2)
    assert _post_run(client, ip="198.51.100.1").status_code == 202
    assert _post_run(client, ip="198.51.100.2").status_code == 202
    refused = _post_run(client, ip="198.51.100.3")
    assert refused.status_code == 429
    assert "Retry-After" in refused.headers


def test_a_run_refused_as_already_active_does_not_use_a_slot(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _busy(_target_id: str) -> None:
        return None

    monkeypatch.setattr(api_module, "create_pending_run", _busy)
    monkeypatch.setattr(settings, "demo_max_runs_per_ip_per_day", 1)
    assert _post_run(client).status_code == 409
    assert _post_run(client).status_code == 409  # still 409, not 429


def _request(headers: dict[str, str], peer: str = "10.0.0.1") -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "headers": raw, "client": (peer, 1234)})


async def test_client_ip_is_stored_hashed_and_respects_trusted_proxy_hops(
    demo_settings: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forwarded = {"X-Forwarded-For": "6.6.6.6, 203.0.113.7, 10.9.9.9"}
    monkeypatch.setattr(settings, "demo_trusted_proxy_hops", 1)
    assert demo.client_ip(_request(forwarded)) == "10.9.9.9"
    monkeypatch.setattr(settings, "demo_trusted_proxy_hops", 2)
    assert demo.client_ip(_request(forwarded)) == "203.0.113.7"
    # No trusted proxy: a client-supplied header is ignored.
    monkeypatch.setattr(settings, "demo_trusted_proxy_hops", 0)
    assert demo.client_ip(_request(forwarded)) == "10.0.0.1"

    async with _memory_db(monkeypatch, demo) as session_factory:
        assert await demo.claim_run("203.0.113.7") is None
        async with session_factory() as session:
            rows = (await session.exec(select(demo.DemoDailyUsage))).all()
    stored = {row.client_ip_hash for row in rows}
    assert "203.0.113.7" not in stored
    assert demo.hash_client_ip("203.0.113.7") in stored
    assert len(demo.hash_client_ip("203.0.113.7")) == 64


# ─── Budgets ──────────────────────────────────────────────────────────────────


async def test_tavily_budget_exhausted_stops_calls_and_explains_why(
    demo_settings: Path, monkeypatch: pytest.MonkeyPatch, httpx_mock
) -> None:
    target = demo.load_demo_targets()[0]
    async with _memory_db(monkeypatch, demo):
        monkeypatch.setattr(settings, "demo_tavily_calls_per_day", 1)
        _tavily_page(httpx_mock, count=1)
        first = await TavilyCollector(target).collect()
        assert first.success
        assert len(httpx_mock.get_requests()) == 1  # 3 queries built, 1 allowed
        assert any("2 of 3 queries failed" in note for note in first.notes)

        second = await TavilyCollector(target).collect()
        assert not second.success
        assert "daily search budget is exhausted" in (second.error or "")
        assert len(httpx_mock.get_requests()) == 1  # no further request


class _CountingClient:
    provider = "nebius"

    def __init__(self) -> None:
        self.calls = 0

    def model_for_route(self, route: str) -> str:
        return f"{route}-model"

    async def complete(self, system: str, user: str, **kwargs: object) -> str:
        self.calls += 1
        return json.dumps({"items": []})


async def test_llm_budget_exhausted_stops_calls_and_explains_why(
    demo_settings: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = demo.load_demo_targets()[0]
    items = [
        EvidenceItem(url=f"https://e.example.org/{i}", title="t", snippet="s", query="q")
        for i in range(25)
    ]
    monkeypatch.setattr(settings, "llm_qualify_enabled", True)
    monkeypatch.setattr(settings, "llm_qualify_max_items", 30)
    monkeypatch.setattr(settings, "demo_llm_calls_per_day", 1)
    client = _CountingClient()
    async with _memory_db(monkeypatch, demo, qualify_module, synth_module) as session_factory:
        async with session_factory() as session:
            run = Run(target_id=target.id, status=RunStatus.RUNNING)
            session.add(run)
            await session.commit()
            await session.refresh(run)

        await qualify_module.qualify_evidence(target, run.id, items, client=client)
        assert client.calls == 1  # 3 batches needed, 1 allowed

        monkeypatch.setattr("orchestrator.synthesizer.providers.get_client", lambda _t: client)
        report_data = RunReportData(
            target_id=target.id,
            target_fqdn=target.fqdn,
            authorization=target.authorization,
            purpose=target.purpose,
            run_id=run.id,
            run_status="success",
            run_started_at=run.started_at,
            run_finished_at=run.started_at,
            collector_results=[],
            bundles=[],
            observables=[],
            errors=[],
        )
        finding, status = await synth_module.synthesize(target, run.id, report_data)
        assert (finding, status) == (None, "skipped")
        assert client.calls == 1  # the synthesis call was not made

        async with session_factory() as session:
            error = (await session.get(Run, run.id)).error or ""
    assert "qualification: the demo's daily LLM budget is exhausted" in error
    assert "synthesis: the demo's daily LLM budget is exhausted" in error


async def test_budgets_are_not_counted_outside_demo_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "demo_mode", False)
    assert await demo.consume_budget("tavily") is True
    assert await demo.consume_budget("llm") is True


async def test_concurrent_budget_checks_never_exceed_the_daily_limit(
    demo_settings: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Two demo runs at once must not both spend the last Tavily call."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'usage.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    monkeypatch.setattr(demo, "get_session", _session)
    monkeypatch.setattr(settings, "demo_tavily_calls_per_day", 5)
    try:
        allowed = await asyncio.gather(*(demo.consume_budget("tavily") for _ in range(20)))
        async with _session() as session:
            rows = (await session.exec(select(demo.DemoDailyUsage))).all()
    finally:
        await engine.dispose()

    assert allowed.count(True) == 5
    assert [(row.scope, row.tavily_calls) for row in rows] == [("global", 5)]


@pytest.mark.parametrize("separator", ["\r", "\x0c", "\x85", "\u2028", "\u2029", "\x1e"])
def test_public_report_withholds_synthesis_behind_any_line_separator(separator: str) -> None:
    """Model text that spells a heading must not end the redaction early."""
    markdown = (
        "# Report\n\n## Errors\n_None._\n\n## Synthesis\n"
        f"Fine.{separator}## Next\n\n**Risk**: `high` — SECRET-JUSTIFICATION\n"
        "\n## Errors\nSECRET-PIVOT\n"
    )

    public = demo.public_report(markdown, "en")

    assert "## Errors\n_None._" in public
    assert public.endswith(
        "## Synthesis\n" + demo.t("demo.synthesis_withheld", language="en") + "\n"
    )
    for forbidden in ("SECRET-", "high", "Fine.", "## Next"):
        assert forbidden not in public


# ─── A full demo run ──────────────────────────────────────────────────────────


def test_no_request_to_disabled_services_during_a_demo_run(client: TestClient, httpx_mock) -> None:
    _tavily_page(httpx_mock)
    accepted = _post_run(client)
    assert accepted.status_code == 202
    run_id = accepted.json()["run_id"]

    run = client.get(f"/demo/runs/{run_id}").json()
    assert run["status"] == "success"
    assert run["sealed"] is True
    assert "error" not in run and "report_path" not in run
    # Every outbound HTTP request went to Tavily (pytest-httpx would have failed
    # any other; the OpenCTI sink would have raised).
    assert {str(request.url) for request in httpx_mock.get_requests()} == {TAVILY_SEARCH_URL}

    manifest = client.get(f"/demo/runs/{run_id}/manifest").json()
    assert "report.md" in manifest["artefacts"]
    verify = client.get("/demo/targets/demo-corp/chain/verify").json()
    assert (verify["ok"], verify["checked"]) == (True, 1)
    assert client.get(f"/demo/runs/{run_id}/evidence").json() == []  # no LLM configured
    assert [r["run_id"] for r in client.get("/demo/targets/demo-corp/runs").json()] == [run_id]


def test_demo_outputs_never_include_risk_level_or_justification(
    client: TestClient, httpx_mock
) -> None:
    _tavily_page(httpx_mock)
    run_id = _post_run(client).json()["run_id"]
    with _db() as conn:
        report_path = conn.execute(
            "SELECT report_path FROM runs WHERE id = ?", (run_id,)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO findings (run_id, target_id, summary, new_since_last_run, risk_level, "
            "risk_justification, suggested_pivots, generated_at, provider, model, duration_ms, "
            "raw_response) VALUES (?, 'demo-corp', 'Neutral summary.', '[]', 'critical', "
            "'SECRET-JUSTIFICATION', ?, '2026-09-08 12:00:00', 'nebius', 'm', 1, "
            "'RAW-MODEL-OUTPUT')",
            (run_id, json.dumps(["pivot"])),
        )
    report = Path(report_path)
    head = report.read_text(encoding="utf-8").split("## Synthesis")[0]
    report.write_text(
        head
        + "## Synthesis\nSECRET-SUMMARY about the entity.\n\n"
        + "**Risk**: `critical` — SECRET-JUSTIFICATION\n\n**Suggested pivots**:\n- SECRET-PIVOT\n",
        encoding="utf-8",
    )

    finding = client.get(f"/demo/runs/{run_id}/finding")
    assert finding.status_code == 200
    # Only that a synthesis exists, by which model, and how long it took.
    assert set(finding.json()) == {
        "run_id",
        "target_id",
        "provider",
        "model",
        "duration_ms",
        "generated_at",
    }
    assert finding.json()["provider"] == "nebius"
    public_report = client.get(f"/demo/runs/{run_id}/report")
    assert public_report.status_code == 200
    assert public_report.text.startswith("> Demonstration on public information.")
    assert "## Synthesis\n_The model's synthesis is not published" in public_report.text
    assert "## Collector status" in public_report.text or "example.com" in public_report.text

    for response in (finding, public_report, client.get(f"/demo/runs/{run_id}")):
        for forbidden in (
            "risk_level",
            "risk_justification",
            "summary",
            "suggested_pivots",
            "Neutral summary",
            "SECRET-",
            "critical",
            "RAW-MODEL-OUTPUT",
        ):
            assert forbidden not in response.text
    # The operator, with the API key, still gets the full finding.
    full = client.get(f"/runs/{run_id}/finding", headers={"X-API-Key": API_KEY}).json()
    assert full["risk_level"] == "critical"


# ─── Seed ─────────────────────────────────────────────────────────────────────


async def test_seed_import_is_idempotent(
    demo_settings: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_dir = tmp_path / "source-run"
    source_dir.mkdir()
    (source_dir / "report.md").write_text(
        "# Report\n\n## Synthesis\nSummary.\n**Risk**: `high` — because\n", encoding="utf-8"
    )
    (source_dir / "qualified_evidence.json").write_text("[]", encoding="utf-8")
    (source_dir / "manifest.json").write_text('{"signature": "hmac-sha256:old"}', encoding="utf-8")
    seed_text = demo.export_seed(
        run={
            "target_id": "demo-corp",
            "started_at": "2026-09-08T12:00:00+00:00",
            "finished_at": "2026-09-08T12:01:00+00:00",
            "status": "success",
            "collectors_run": "tavily",
            "new_observables": 2,
            "error": "internal detail",
        },
        finding={
            "summary": "Summary.",
            "risk_level": "high",
            "risk_justification": "because",
            "suggested_pivots": ["p"],
            "new_since_last_run": [],
            "provider": "nebius",
            "model": "m",
            "raw_response": "RAW",
        },
        evidence=[
            {
                "url": "https://news.example.org/a",
                "title": "A",
                "category": "litigation",
                "relevance": "high",
                "confidence": 0.9,
                "rationale": "about the entity",
                "provider": "nebius",
                "model": "fast",
            }
        ],
        run_dir=source_dir,
    )
    # The seed carries no risk assessment, signature, raw output or error text.
    for forbidden in (
        "risk_level",
        "because",
        "hmac-sha256",
        "RAW",
        "internal detail",
        "**Risk**",
        "Summary.",
        "suggested_pivots",
    ):
        assert forbidden not in seed_text
    seed_dir = tmp_path / "seed"
    seed_dir.mkdir()
    (seed_dir / "demo-corp-01.json").write_text(seed_text, encoding="utf-8")

    async with _memory_db(monkeypatch, demo) as session_factory:
        assert await demo.import_seed_if_empty(seed_dir) == 1
        assert await demo.import_seed_if_empty(seed_dir) == 0  # already has runs

        async with session_factory() as session:
            runs = (await session.exec(select(Run))).all()
            finding = (await session.exec(select(FindingRecord))).one()
            verdict = await verify_target_chain(
                target_id="demo-corp", secret_key=SIGNING_KEY, session=session
            )
    assert len(runs) == 1
    assert runs[0].manifest_sha256 is not None
    assert Path(runs[0].report_path).parent.name == f"run-{runs[0].id}"
    assert (finding.summary, finding.risk_level, finding.risk_justification) == ("", "unknown", "")
    assert (finding.provider, finding.model) == ("nebius", "m")
    assert (verdict["ok"], verdict["checked"]) == (True, 1)


def test_shipped_allowlist_is_a_valid_demo_configuration(
    demo_settings: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shipped = Path(__file__).parents[2] / "demo" / "targets.demo.yaml"
    monkeypatch.setattr(settings, "demo_targets_file", str(shipped))
    monkeypatch.setattr(settings, "nebius_api_key", "test-token")
    monkeypatch.setattr(settings, "llm_model_reasoning", "nvidia/reasoning-model")
    monkeypatch.setattr(settings, "llm_model_fast", "nvidia/fast-model")
    demo.validate_demo_mode()
    assert all(target.fqdn.startswith("example.") for target in demo.load_demo_targets())


@pytest.mark.parametrize(
    ("setting", "expected"),
    [
        ("nebius_api_key", "NEBIUS_API_KEY must be set"),
        ("llm_model_reasoning", "LLM_MODEL_REASONING must name a Nemotron model"),
        ("llm_model_fast", "LLM_MODEL_FAST must name a Nemotron model"),
    ],
)
def test_nebius_targets_need_a_key_and_both_model_routes(
    demo_settings: Path, monkeypatch: pytest.MonkeyPatch, setting: str, expected: str
) -> None:
    # The shipped allowlist synthesises with ``llm: nebius``; a half-filled
    # .env must stop the service instead of failing every run in public.
    shipped = Path(__file__).parents[2] / "demo" / "targets.demo.yaml"
    monkeypatch.setattr(settings, "demo_targets_file", str(shipped))
    monkeypatch.setattr(settings, "llm_provider", "nebius")  # the fixture turns synthesis off
    monkeypatch.setattr(settings, "nebius_api_key", "test-token")
    monkeypatch.setattr(settings, "llm_model_reasoning", "nvidia/reasoning-model")
    monkeypatch.setattr(settings, "llm_model_fast", "nvidia/fast-model")
    monkeypatch.setattr(settings, setting, "")
    with pytest.raises(RuntimeError, match=expected):
        demo.validate_demo_mode()


def test_nebius_settings_are_not_required_when_synthesis_is_off(
    demo_settings: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # LLM_PROVIDER=none builds no client at all (providers.get_client), so the
    # shipped allowlist must start without Nebius settings.
    shipped = Path(__file__).parents[2] / "demo" / "targets.demo.yaml"
    monkeypatch.setattr(settings, "demo_targets_file", str(shipped))
    monkeypatch.setattr(settings, "llm_provider", "none")
    monkeypatch.setattr(settings, "nebius_api_key", "")
    monkeypatch.setattr(settings, "llm_model_reasoning", "")
    monkeypatch.setattr(settings, "llm_model_fast", "")
    demo.validate_demo_mode()


@pytest.mark.parametrize(
    ("llm", "provider", "expected"),
    [
        ("anthropic", "anthropic", "ANTHROPIC_API_KEY must be set"),
        ("openai", "openai", "OPENAI_API_KEY must be set"),
        ("openai", "nebius", "NEBIUS_API_KEY must be set"),
    ],
)
def test_every_cloud_provider_a_demo_target_uses_needs_its_key(
    demo_settings: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    llm: str,
    provider: str,
    expected: str,
) -> None:
    # The guard follows providers.get_client: whatever client a target would
    # build must have its key, not only the Nebius route.
    path = tmp_path / "targets.cloud.yaml"
    path.write_text(
        _TARGETS.format(
            target_id="cloud-corp", report_dir=tmp_path / "r", openosint="false"
        ).replace("    language: en\n", f"    language: en\n    llm: {llm}\n"),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "demo_targets_file", str(path))
    monkeypatch.setattr(settings, "llm_provider", provider)
    for name in ("anthropic_api_key", "openai_api_key", "nebius_api_key"):
        monkeypatch.setattr(settings, name, "")
    with pytest.raises(RuntimeError, match=expected):
        demo.validate_demo_mode()


def test_local_targets_need_no_cloud_key_whatever_the_global_provider(
    demo_settings: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A target without ``llm:`` defaults to ``local`` and always gets Ollama
    # (providers.get_client), so a cloud LLM_PROVIDER must not demand its key.
    monkeypatch.setattr(settings, "llm_provider", "anthropic")
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    demo.validate_demo_mode()  # the fixture's targets carry no ``llm:``


def test_demo_page_has_the_console_security_headers(client: TestClient) -> None:
    resp = client.get("/demo")
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    nonce = csp.split("script-src 'nonce-", 1)[1].split("'", 1)[0]
    assert f'<script nonce="{nonce}">' in resp.text
    assert f'<style nonce="{nonce}">' in resp.text
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert resp.headers["Cache-Control"] == "no-store"


def test_public_chain_verify_is_cached_briefly_and_counted(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from orchestrator import metrics

    api_module._demo_verify_cache.clear()
    calls: list[str] = []
    real = api_module.verify_target_chain

    async def _counting(**kwargs):
        calls.append(kwargs["target_id"])
        return await real(**kwargs)

    monkeypatch.setattr(api_module, "verify_target_chain", _counting)
    before = (
        metrics.sample(
            "osint_orchestrator_evidence_chain_verify_total",
            {"target_id": "demo-corp", "outcome": "ok"},
        )
        or 0.0
    )

    first = client.get("/demo/targets/demo-corp/chain/verify").json()
    second = client.get("/demo/targets/demo-corp/chain/verify").json()

    assert first["ok"] is True and second == first
    assert calls == ["demo-corp"]  # the second request was served from the cache
    after = metrics.sample(
        "osint_orchestrator_evidence_chain_verify_total",
        {"target_id": "demo-corp", "outcome": "ok"},
    )
    assert after - before == 2  # every request is counted, cached or not


def test_public_target_view_has_no_authorization_text(demo_settings: Path) -> None:
    target: Target = demo.load_demo_targets()[0]
    assert set(demo.public_target(target)) == {"id", "fqdn", "search_terms"}
