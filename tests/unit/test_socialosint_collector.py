"""
Unit tests for the SocialOSINT collector.

All tests are offline — no real network calls.  HTTP interactions are mocked
with pytest-httpx.  The fixture data lives in tests/fixtures/socialosint_response.json
and represents real (anonimised) API responses from the OWASP SocialOSINT
web service.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
from unittest.mock import AsyncMock

import httpx
import pytest

from orchestrator.collectors.socialosint import (
    SocialOSINTCollector,
    _parse_available_platforms,
    _profile_url,
)
from orchestrator.models import CollectorName, CollectorSet, Target

FIXTURES = json.loads(
    (pathlib.Path(__file__).parent.parent / "fixtures" / "socialosint_response.json").read_text()
)

SOCIALOSINT_BASE = "http://socialosint:8000"


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _target(**kwargs) -> Target:
    defaults = dict(id="t1", fqdn="example.com", authorization="self-owned", purpose="test")
    defaults.update(kwargs)
    return Target(**defaults)


def _collector(target: Target | None = None) -> SocialOSINTCollector:
    if target is None:
        t = _target()
        t.collectors.socialosint.enabled = True
        t.collectors.socialosint.usernames = ["testhandle"]
        t.collectors.socialosint.platforms = ["twitter", "github"]
        target = t
    return SocialOSINTCollector(target)


def _register_happy_path(httpx_mock, *, poll_once: bool = True) -> None:
    """Register the full happy-path sequence of API calls."""
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/platforms",
        json=FIXTURES["platforms_response"],
    )
    httpx_mock.add_response(
        method="POST",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions",
        json=FIXTURES["session_create_response"],
    )
    httpx_mock.add_response(
        method="POST",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{FIXTURES['session_create_response']['id']}/analyse",
        json=FIXTURES["analyse_response"],
    )
    if poll_once:
        httpx_mock.add_response(
            method="GET",
            url=f"{SOCIALOSINT_BASE}/api/v1/jobs/{FIXTURES['analyse_response']['job_id']}",
            json=FIXTURES["job_complete_response"],
        )
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{FIXTURES['session_create_response']['id']}/export",
        json=FIXTURES["session_export_response"],
    )
    httpx_mock.add_response(
        method="DELETE",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{FIXTURES['session_create_response']['id']}",
        status_code=204,
    )


# ─── Platform availability helpers ───────────────────────────────────────────


def test_parse_available_platforms_list() -> None:
    assert _parse_available_platforms(["twitter", "github"]) == {"twitter", "github"}


def test_parse_available_platforms_dict_platforms_key() -> None:
    assert _parse_available_platforms({"platforms": ["twitter"]}) == {"twitter"}


def test_parse_available_platforms_dict_available_key() -> None:
    assert _parse_available_platforms({"available": ["hackernews"]}) == {"hackernews"}


def test_parse_available_platforms_unknown_shape() -> None:
    assert _parse_available_platforms({"foo": "bar"}) == set()


# ─── Profile URL construction ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("platform", "handle", "expected"),
    [
        ("twitter", "alice", "https://twitter.com/alice"),
        ("reddit", "alice", "https://reddit.com/u/alice"),
        ("github", "alice", "https://github.com/alice"),
        ("bluesky", "alice.bsky.social", "https://bsky.app/profile/alice.bsky.social"),
        ("hackernews", "alice", "https://news.ycombinator.com/user?id=alice"),
        ("mastodon", "alice@infosec.exchange", "https://infosec.exchange/@alice"),
        ("mastodon", "alice", None),  # no instance → no URL
    ],
)
def test_profile_url(platform: str, handle: str, expected: str | None) -> None:
    assert _profile_url(platform, handle) == expected


# ─── Misconfiguration: no usernames / invalid platforms ──────────────────────


async def test_no_usernames_returns_failure(httpx_mock) -> None:
    target = _target()
    target.collectors.socialosint.enabled = True
    target.collectors.socialosint.usernames = []
    result = await SocialOSINTCollector(target).collect()
    assert result.success is False
    assert result.error is not None
    assert "usernames" in result.error.lower()
    assert result.observables == []
    # No HTTP calls were made
    assert httpx_mock.get_requests() == []


def test_unknown_platform_rejected_at_target_load() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        Target(
            id="t1",
            fqdn="example.com",
            authorization="self-owned",
            purpose="test",
            collectors={
                "socialosint": {
                    "enabled": True,
                    "usernames": ["testhandle"],
                    "platforms": ["twiter"],
                }
            },
        )


async def test_unknown_platform_returns_failure_when_injected_post_load(httpx_mock) -> None:
    target = _target()
    target.collectors.socialosint.enabled = True
    target.collectors.socialosint.usernames = ["testhandle"]
    # Assignment bypasses pydantic creation-time validation; collector still guards it.
    target.collectors.socialosint.platforms = ["twiter"]

    result = await SocialOSINTCollector(target).collect()

    assert result.success is False
    assert result.error is not None
    assert "unsupported platform" in result.error.lower()
    assert httpx_mock.get_requests() == []


# ─── enabled: false by default ───────────────────────────────────────────────


def test_socialosint_disabled_by_default() -> None:
    """A target without an explicit socialosint block has enabled=False."""
    target = _target()
    assert target.collectors.socialosint.enabled is False


def test_collector_set_default_disabled() -> None:
    cs = CollectorSet()
    assert cs.socialosint.enabled is False


# ─── Happy path — observables and relationships ───────────────────────────────


async def test_happy_path_produces_user_account_observables(httpx_mock) -> None:
    _register_happy_path(httpx_mock)
    result = await _collector().collect()

    assert result.success is True
    assert result.collector == CollectorName.SOCIALOSINT
    assert result.target_fqdn == "example.com"

    account_obs = [o for o in result.observables if o.type == "user-account"]
    # twitter/testhandle + github/testhandle = 2 accounts with distinct values
    assert len(account_obs) == 2
    # The platform is context only; the normaliser keeps account_type="generic".
    assert {o.extra["platform"] for o in account_obs} == {"twitter", "github"}
    # Values encode platform so the same handle on two platforms is unambiguous
    assert {o.value for o in account_obs} == {"twitter:testhandle", "github:testhandle"}


async def test_happy_path_produces_url_observables(httpx_mock) -> None:
    _register_happy_path(httpx_mock)
    result = await _collector().collect()

    url_obs = [o for o in result.observables if o.type == "url"]
    url_values = {o.value for o in url_obs}
    assert "https://twitter.com/testhandle" in url_values
    assert "https://github.com/testhandle" in url_values


async def test_happy_path_user_account_to_url_relationships(httpx_mock) -> None:
    _register_happy_path(httpx_mock)
    result = await _collector().collect()

    ua_url_rels = [
        r
        for r in result.relationships
        if r.source_type == "user-account" and r.target_type == "url"
    ]
    assert len(ua_url_rels) == 2  # one per platform (twitter, github)
    # Source values use platform:handle scheme
    src_values = {r.source_value for r in ua_url_rels}
    assert src_values == {"twitter:testhandle", "github:testhandle"}


async def test_happy_path_user_account_to_domain_relationships(httpx_mock) -> None:
    _register_happy_path(httpx_mock)
    result = await _collector().collect()

    ua_domain_rels = [
        r
        for r in result.relationships
        if r.source_type == "user-account" and r.target_type == "domain-name"
    ]
    assert len(ua_domain_rels) == 2
    assert all(r.target_value == "example.com" for r in ua_domain_rels)
    assert all(r.relationship_type == "related-to" for r in ua_domain_rels)


async def test_happy_path_report_goes_to_notes(httpx_mock) -> None:
    _register_happy_path(httpx_mock)
    result = await _collector().collect()

    assert result.notes
    combined = " ".join(result.notes)
    assert "no verificado" in combined.lower() or "socialosint" in combined.lower()
    assert "osint analysis" in combined.lower()  # text from the fixture report


async def test_notes_follow_the_target_language(httpx_mock) -> None:
    """ADR-004: operator-facing note text is localised, not hard-coded Spanish."""
    _register_happy_path(httpx_mock)
    target = _target(language="en")
    target.collectors.socialosint.enabled = True
    target.collectors.socialosint.usernames = ["testhandle"]
    target.collectors.socialosint.platforms = ["twitter", "github"]

    result = await _collector(target).collect()

    assert result.notes[0].startswith("[SocialOSINT analysis, unverified]\n\n")
    assert "no verificado" not in " ".join(result.notes)


def test_skipped_platforms_note_is_localised() -> None:
    collector = _collector()
    es = collector._build_result({}, "", ["mastodon"], language="es").notes
    en = collector._build_result({}, "", ["mastodon"], language="en").notes
    assert es == ["Plataformas omitidas por falta de credenciales: mastodon"]
    assert en == ["Platforms skipped for lack of credentials: mastodon"]


# ─── Deterministic ids: casing must not matter ────────────────────────────────


async def test_user_account_id_is_case_insensitive(httpx_mock) -> None:
    """Upper-cased handle must produce the same user_id (and thus same STIX id)."""
    from orchestrator.normalizer.stix import normalize

    # Build two results: one with lowercase, one with uppercase handle
    target_lower = _target()
    target_lower.collectors.socialosint.enabled = True
    target_lower.collectors.socialosint.usernames = ["testhandle"]
    target_lower.collectors.socialosint.platforms = ["github"]

    target_upper = _target()
    target_upper.collectors.socialosint.enabled = True
    target_upper.collectors.socialosint.usernames = ["TestHandle"]
    target_upper.collectors.socialosint.platforms = ["github"]

    # Both register the same platform + export
    for _ in range(2):
        httpx_mock.add_response(
            method="GET",
            url=f"{SOCIALOSINT_BASE}/api/v1/platforms",
            json=["github"],
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{SOCIALOSINT_BASE}/api/v1/sessions",
            json=FIXTURES["session_create_response"],
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{FIXTURES['session_create_response']['id']}/analyse",
            json=FIXTURES["analyse_response"],
        )
        httpx_mock.add_response(
            method="GET",
            url=f"{SOCIALOSINT_BASE}/api/v1/jobs/{FIXTURES['analyse_response']['job_id']}",
            json=FIXTURES["job_complete_response"],
        )
        httpx_mock.add_response(
            method="GET",
            url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{FIXTURES['session_create_response']['id']}/export",
            json=FIXTURES["session_export_response"],
        )
        httpx_mock.add_response(
            method="DELETE",
            url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{FIXTURES['session_create_response']['id']}",
            status_code=204,
        )

    result_lower = await SocialOSINTCollector(target_lower).collect()
    result_upper = await SocialOSINTCollector(target_upper).collect()

    bundle_lower = normalize(result_lower)
    bundle_upper = normalize(result_upper)

    ua_ids_lower = {obj["id"] for obj in bundle_lower.objects if obj.get("type") == "user-account"}
    ua_ids_upper = {obj["id"] for obj in bundle_upper.objects if obj.get("type") == "user-account"}
    assert ua_ids_lower == ua_ids_upper


async def test_same_handle_two_platforms_produces_distinct_stix_ids(httpx_mock) -> None:
    """
    The same handle on two different platforms (e.g. 'alice' on GitHub and
    Bluesky) must produce two user-account observables with DIFFERENT STIX ids.
    """
    from orchestrator.normalizer.stix import normalize

    target = _target()
    target.collectors.socialosint.enabled = True
    target.collectors.socialosint.usernames = ["alice"]
    target.collectors.socialosint.platforms = ["github", "bluesky"]

    session_id = FIXTURES["session_create_response"]["id"]
    job_id = FIXTURES["analyse_response"]["job_id"]

    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/platforms",
        json=["github", "bluesky", "twitter"],
    )
    httpx_mock.add_response(
        method="POST",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions",
        json=FIXTURES["session_create_response"],
    )
    httpx_mock.add_response(
        method="POST",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{session_id}/analyse",
        json=FIXTURES["analyse_response"],
    )
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/jobs/{job_id}",
        json=FIXTURES["job_complete_response"],
    )
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{session_id}/export",
        json=FIXTURES["session_export_response"],
    )
    httpx_mock.add_response(
        method="DELETE",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{session_id}",
        status_code=204,
    )

    result = await SocialOSINTCollector(target).collect()

    account_obs = [o for o in result.observables if o.type == "user-account"]
    assert len(account_obs) == 2

    # Values must be distinct (platform-namespaced)
    values = {o.value for o in account_obs}
    assert values == {"github:alice", "bluesky:alice"}

    # STIX ids must be distinct
    bundle = normalize(result)
    ua_ids = [obj["id"] for obj in bundle.objects if obj.get("type") == "user-account"]
    assert len(ua_ids) == 2
    assert ua_ids[0] != ua_ids[1]

    # Each account must have its own relationship to the target domain
    domain_rels = [
        r
        for r in result.relationships
        if r.source_type == "user-account" and r.target_type == "domain-name"
    ]
    src_values = {r.source_value for r in domain_rels}
    assert src_values == {"github:alice", "bluesky:alice"}


# ─── Platform without credentials → skipped, others run ──────────────────────


async def test_platform_without_credentials_is_skipped(httpx_mock) -> None:
    """
    mastodon is requested but the service only has twitter + github.
    mastodon accounts must be absent; twitter/github must be present.
    """
    target = _target()
    target.collectors.socialosint.enabled = True
    target.collectors.socialosint.usernames = ["testhandle"]
    target.collectors.socialosint.platforms = ["twitter", "mastodon"]

    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/platforms",
        json=["twitter", "github"],  # mastodon NOT available
    )
    # Session is created with only twitter
    session_id = FIXTURES["session_create_response"]["id"]
    httpx_mock.add_response(
        method="POST",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions",
        json=FIXTURES["session_create_response"],
    )
    httpx_mock.add_response(
        method="POST",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{session_id}/analyse",
        json=FIXTURES["analyse_response"],
    )
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/jobs/{FIXTURES['analyse_response']['job_id']}",
        json=FIXTURES["job_complete_response"],
    )
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{session_id}/export",
        json=FIXTURES["session_export_response"],
    )
    httpx_mock.add_response(
        method="DELETE",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{session_id}",
        status_code=204,
    )

    result = await SocialOSINTCollector(target).collect()

    assert result.success is True
    platforms_in_accounts = {
        o.extra["platform"] for o in result.observables if o.type == "user-account"
    }
    assert "mastodon" not in platforms_in_accounts
    assert "twitter" in platforms_in_accounts
    # Skip note should mention mastodon
    assert any("mastodon" in n.lower() for n in result.notes)


async def test_all_platforms_missing_returns_failure(httpx_mock) -> None:
    target = _target()
    target.collectors.socialosint.enabled = True
    target.collectors.socialosint.usernames = ["testhandle"]
    target.collectors.socialosint.platforms = ["mastodon"]

    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/platforms",
        json=["twitter", "github"],  # mastodon NOT available
    )

    result = await SocialOSINTCollector(target).collect()

    assert result.success is False
    assert result.error is not None
    assert result.observables == []
    assert "credential" in result.error.lower() or "platform" in result.error.lower()


async def test_platforms_endpoint_500_returns_failure(httpx_mock) -> None:
    """A 500 from /api/v1/platforms means the service is broken, not 'no credentials'."""
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/platforms",
        status_code=500,
    )

    result = await _collector().collect()

    assert result.success is False


# ─── Timeout → CollectorResult(success=False) ────────────────────────────────


async def test_timeout_returns_failure(httpx_mock) -> None:
    httpx_mock.add_exception(httpx.TimeoutException("timed out"))

    result = await _collector().collect()

    assert result.success is False
    assert result.error is not None
    assert "timeout" in result.error.lower()


# ─── Service unreachable → CollectorResult(success=False) ────────────────────


async def test_connect_error_returns_failure(httpx_mock) -> None:
    httpx_mock.add_exception(httpx.ConnectError("connection refused"))

    result = await _collector().collect()

    assert result.success is False
    assert result.error is not None


# ─── Polling: running then complete ──────────────────────────────────────────


async def test_job_polling_waits_for_completion(httpx_mock) -> None:
    """Collector polls twice (running → complete) before fetching the report."""
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/platforms",
        json=["twitter", "github"],
    )
    session_id = FIXTURES["session_create_response"]["id"]
    job_id = FIXTURES["analyse_response"]["job_id"]

    httpx_mock.add_response(
        method="POST",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions",
        json=FIXTURES["session_create_response"],
    )
    httpx_mock.add_response(
        method="POST",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{session_id}/analyse",
        json=FIXTURES["analyse_response"],
    )
    # First poll: running
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/jobs/{job_id}",
        json=FIXTURES["job_running_response"],
    )
    # Second poll: complete
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/jobs/{job_id}",
        json=FIXTURES["job_complete_response"],
    )
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{session_id}/export",
        json=FIXTURES["session_export_response"],
    )
    httpx_mock.add_response(
        method="DELETE",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{session_id}",
        status_code=204,
    )

    # Patch sleep to avoid actual delay in tests
    import unittest.mock

    with unittest.mock.patch("orchestrator.collectors.socialosint.asyncio.sleep"):
        result = await _collector().collect()

    assert result.success is True
    assert any(o.type == "user-account" for o in result.observables)


async def test_timeout_is_wall_clock_and_session_is_deleted(httpx_mock, monkeypatch) -> None:
    target = _target()
    target.collectors.socialosint.enabled = True
    target.collectors.socialosint.usernames = ["testhandle"]
    target.collectors.socialosint.platforms = ["twitter"]
    target.collectors.socialosint.timeout_seconds = 1
    collector = SocialOSINTCollector(target)

    session_id = FIXTURES["session_create_response"]["id"]
    httpx_mock.add_response(
        method="GET",
        url=f"{SOCIALOSINT_BASE}/api/v1/platforms",
        json=FIXTURES["platforms_response"],
    )
    httpx_mock.add_response(
        method="POST",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions",
        json=FIXTURES["session_create_response"],
    )
    httpx_mock.add_response(
        method="POST",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{session_id}/analyse",
        json=FIXTURES["analyse_response"],
    )
    httpx_mock.add_response(
        method="DELETE",
        url=f"{SOCIALOSINT_BASE}/api/v1/sessions/{session_id}",
        status_code=204,
    )

    async def _slow_wait_for_job(client, job_id):  # noqa: ANN001, ARG001
        await asyncio.sleep(2)

    monkeypatch.setattr(collector, "_wait_for_job", _slow_wait_for_job)

    started = asyncio.get_running_loop().time()
    result = await collector.collect()
    elapsed = asyncio.get_running_loop().time() - started

    assert result.success is False
    assert result.error is not None
    assert "timeout" in result.error.lower()
    assert elapsed < 1.6
    assert any(
        req.method == "DELETE" and req.url.path == f"/api/v1/sessions/{session_id}"
        for req in httpx_mock.get_requests()
    )


# ─── STIX user-account carries platform-specific account_type ────────────────


async def test_stix_bundle_user_accounts_stay_generic_and_link_to_the_domain(httpx_mock) -> None:
    """
    account_type is an ID-contributing property of UserAccount, so it must be
    "generic" for every producer or the same account gets two OpenCTI objects;
    the platform travels as x_platform. And the user-account → domain-name
    edges only survive normalisation if the collector emits the domain itself.
    """
    from orchestrator.normalizer.stix import normalize

    _register_happy_path(httpx_mock)
    result = await _collector().collect()
    bundle = normalize(result)

    ua_objects = [obj for obj in bundle.objects if getattr(obj, "type", None) == "user-account"]
    assert ua_objects, "expected user-account observables in the bundle"
    assert {obj["account_type"] for obj in ua_objects} == {"generic"}
    assert {obj["x_platform"] for obj in ua_objects} == {"twitter", "github"}

    domains = [obj for obj in bundle.objects if getattr(obj, "type", None) == "domain-name"]
    assert [d["value"] for d in domains] == ["example.com"]
    ua_ids = {obj["id"] for obj in ua_objects}
    rels = [obj for obj in bundle.objects if getattr(obj, "type", None) == "relationship"]
    to_domain = [
        r for r in rels if r["source_ref"] in ua_ids and r["target_ref"] == domains[0]["id"]
    ]
    assert len(to_domain) == len(ua_objects), "every account must be linked to the target domain"


# ─── Pipeline integration: _get_collectors wires up SocialOSINT ──────────────


@pytest.mark.asyncio
async def test_pipeline_runs_socialosint_collector(
    tmp_path,
    monkeypatch,
    httpx_mock,
) -> None:
    """
    Real _get_collectors + SocialOSINT enabled target + httpx_mock happy path.
    Verifies:
      - run finishes with status SUCCESS
      - 'socialosint' appears in run.collectors_run
      - RunObservable rows contain at least one user-account
    """
    from contextlib import asynccontextmanager
    from datetime import UTC, datetime

    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool
    from sqlmodel import SQLModel, select
    from sqlmodel.ext.asyncio.session import AsyncSession

    import orchestrator.pipeline as pipeline_module
    from orchestrator.models import Run, RunObservable, RunStatus
    from orchestrator.pipeline import run_target_pipeline

    # ── in-memory DB ──────────────────────────────────────────────────────────
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=True) as session:
            yield session

    monkeypatch.setattr(pipeline_module, "get_session", _session)

    # ── stub out synthesizer and OpenCTISink ─────────────────────────────────
    async def _no_synth(*a, **kw):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _no_synth)
    monkeypatch.setattr(pipeline_module, "OpenCTISink", AsyncMock)

    import orchestrator.alerts as alerts_mod

    monkeypatch.setattr(alerts_mod, "build_notifiers", lambda language=None: [])

    # ── target: only SocialOSINT enabled ─────────────────────────────────────
    target = Target(
        id="pipeline-so-test",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        report_dir=str(tmp_path),
    )
    target.collectors.openosint.enabled = False
    target.collectors.spiderfoot.enabled = False
    target.collectors.socialosint.enabled = True
    target.collectors.socialosint.usernames = ["testhandle"]
    target.collectors.socialosint.platforms = ["twitter", "github"]

    # ── register httpx happy-path responses ──────────────────────────────────
    _register_happy_path(httpx_mock)

    # ── create a pending run ──────────────────────────────────────────────────
    async with _session() as session:
        run = Run(
            target_id=target.id,
            started_at=datetime.now(UTC),
            status=RunStatus.PENDING,
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

    await run_target_pipeline(target, run_id)

    # ── assertions ────────────────────────────────────────────────────────────
    async with _session() as session:
        run_after = await session.get(Run, run_id)
        assert run_after is not None
        assert run_after.status == RunStatus.SUCCESS
        assert "socialosint" in run_after.collectors_run

        rows = (
            await session.exec(select(RunObservable).where(RunObservable.run_id == run_id))
        ).all()
        ua_rows = [r for r in rows if r.stix_type == "user-account"]
        assert ua_rows, "expected at least one user-account in RunObservable"


async def test_pipeline_socialosint_disabled_by_default(
    tmp_path,
    monkeypatch,
) -> None:
    """A target without explicit socialosint config must not run the collector."""
    from contextlib import asynccontextmanager
    from datetime import UTC, datetime

    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool
    from sqlmodel import SQLModel
    from sqlmodel.ext.asyncio.session import AsyncSession

    import orchestrator.pipeline as pipeline_module
    from orchestrator.models import Run, RunStatus
    from orchestrator.pipeline import run_target_pipeline

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=True) as session:
            yield session

    monkeypatch.setattr(pipeline_module, "get_session", _session)

    async def _no_synth(*a, **kw):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _no_synth)
    monkeypatch.setattr(pipeline_module, "OpenCTISink", AsyncMock)

    import orchestrator.alerts as alerts_mod

    monkeypatch.setattr(alerts_mod, "build_notifiers", lambda language=None: [])

    # Default target — no socialosint block means enabled=False
    target = Target(
        id="pipeline-default-test",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        report_dir=str(tmp_path),
    )
    target.collectors.openosint.enabled = False
    target.collectors.spiderfoot.enabled = False
    # socialosint defaults to enabled=False — no change needed

    async with _session() as session:
        run = Run(
            target_id=target.id,
            started_at=datetime.now(UTC),
            status=RunStatus.PENDING,
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

    await run_target_pipeline(target, run_id)

    async with _session() as session:
        run_after = await session.get(Run, run_id)
        assert run_after is not None
        assert "socialosint" not in (run_after.collectors_run or "")
