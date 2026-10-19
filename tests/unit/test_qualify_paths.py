"""
Defensive paths of evidence qualification.

The model's answer is untrusted: every field is validated before a row is
stored, and anything malformed leaves the item unqualified rather than
inventing a label. These tests pin each rejection and the run-error summary
written when the provider calls themselves fail.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.synthesizer.qualify as qualify_module
from orchestrator.config import settings
from orchestrator.models import EvidenceItem, EvidenceQualification, Run, RunStatus, Target
from orchestrator.synthesizer.qualify import (
    _extract_json,
    _validated_rows,
    load_run_qualifications,
    persist_qualifications,
    qualify_evidence,
)


def _target() -> Target:
    return Target(id="t1", fqdn="example.com", authorization="self-owned", purpose="test")


def _items(count: int) -> list[EvidenceItem]:
    return [
        EvidenceItem(url=f"https://example.com/{i}", title=f"t{i}", snippet="s", query="q")
        for i in range(count)
    ]


def _entry(index: object = 0, **overrides: object) -> dict:
    entry: dict = {
        "index": index,
        "category": "adverse_media",
        "relevance": "high",
        "confidence": 0.8,
        "rationale": "names the entity",
    }
    entry.update(overrides)
    return entry


@pytest.fixture
async def db(monkeypatch: pytest.MonkeyPatch):
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

    monkeypatch.setattr(qualify_module, "get_session", _session)
    yield _session
    await engine.dispose()


# ── Parsing the answer ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('```json\n{"items": []}\n```', {"items": []}),
        ('Sure! {"items": []} Hope it helps.', {"items": []}),
        ("no json here", None),
        ("{not: valid}", None),
        ("```json\n[1, 2]\n```", None),
    ],
    ids=["fenced", "embedded", "no-object", "invalid-json", "not-an-object"],
)
def test_extract_json(raw: str, expected: dict | None) -> None:
    assert _extract_json(raw) == expected


def test_the_unmodified_entry_is_valid() -> None:
    """Control for the rejection cases below: each one breaks exactly one field."""
    rows = _validated_rows(
        payload={"items": [_entry()]},
        batch=_items(2),
        run_id=1,
        target_id="t1",
        provider="p",
        model="m",
    )
    assert [(r.url, r.category, r.relevance) for r in rows] == [
        ("https://example.com/0", "adverse_media", "high")
    ]


@pytest.mark.parametrize(
    "payload",
    [
        {"items": "not a list"},
        {"items": ["not a mapping"]},
        {"items": [_entry(index=5)]},
        {"items": [_entry(index=-1)]},
        {"items": [_entry(index="0")]},
        {"items": [_entry(category="rumour")]},
        {"items": [_entry(category=None)]},
        {"items": [_entry(relevance="maybe")]},
        {"items": [_entry(relevance=1)]},
        {"items": [_entry(confidence=True)]},
        {"items": [_entry(confidence="0.9")]},
        {"items": [_entry(confidence=1.5)]},
        {"items": [_entry(confidence=-0.1)]},
        {"items": [_entry(rationale=None)]},
    ],
    ids=[
        "items-not-list",
        "entry-not-mapping",
        "index-out-of-range",
        "index-negative",
        "index-string",
        "unknown-category",
        "missing-category",
        "unknown-relevance",
        "relevance-not-string",
        "confidence-bool",
        "confidence-string",
        "confidence-above-1",
        "confidence-below-0",
        "rationale-missing",
    ],
)
def test_malformed_entries_produce_no_row(payload: dict) -> None:
    rows = _validated_rows(
        payload=payload, batch=_items(2), run_id=1, target_id="t1", provider="p", model="m"
    )
    assert rows == []


def test_valid_entry_is_flattened_and_truncated() -> None:
    rationale = "line one\nline two " + "x" * 400
    (row,) = _validated_rows(
        payload={"items": [_entry(index=1, confidence=1, rationale=rationale)]},
        batch=_items(2),
        run_id=1,
        target_id="t1",
        provider="p",
        model="m",
    )
    assert row.url == "https://example.com/1"
    assert row.confidence == 1.0
    assert "\n" not in row.rationale
    assert len(row.rationale) == qualify_module._MAX_RATIONALE_LEN


# ── Gating and failure summary ────────────────────────────────────────────────


class _Client:
    provider = "fake"

    def __init__(self, errors: list[Exception]) -> None:
        self.errors = errors
        self.calls = 0

    @staticmethod
    def model_for_route(route: str) -> str:
        return "fake-fast"

    async def complete(self, *_args, **_kwargs) -> str:
        self.calls += 1
        raise self.errors[(self.calls - 1) % len(self.errors)]


async def test_no_items_or_no_client_skips_qualification(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_qualify_enabled", True)
    monkeypatch.setattr(settings, "llm_qualify_max_items", 30)
    assert await qualify_evidence(_target(), 1, []) == []
    monkeypatch.setattr(qualify_module, "get_client", lambda target: None)
    assert await qualify_evidence(_target(), 1, _items(1)) == []


async def test_distinct_failures_are_summarised_on_the_run(
    db, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "llm_qualify_enabled", True)
    monkeypatch.setattr(settings, "llm_qualify_max_items", 30)
    async with db() as session:
        run = Run(
            target_id="t1",
            started_at=datetime.now(UTC),
            status=RunStatus.RUNNING,
            error="tavily: quota",
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id
    assert run_id is not None

    # Two batches of five; each call fails with a different message.
    client = _Client([RuntimeError("timeout"), RuntimeError("HTTP 503")])
    rows = await qualify_evidence(_target(), run_id, _items(7), client=client)

    assert rows == []
    assert client.calls == 2, "a failed call is not retried by the qualifier itself"
    async with db() as session:
        stored = await session.get(Run, run_id)
    assert stored is not None
    assert stored.error == "tavily: quota; qualification: timeout; +1 more"


# ── Persistence ───────────────────────────────────────────────────────────────


async def test_persist_nothing_opens_no_session(monkeypatch: pytest.MonkeyPatch) -> None:
    def _must_not_open():
        raise AssertionError("no session for an empty batch")

    monkeypatch.setattr(qualify_module, "get_session", _must_not_open)
    await persist_qualifications([])


async def test_load_run_qualifications_opens_its_own_session(db) -> None:
    def _row(run_id: int, url: str) -> EvidenceQualification:
        return EvidenceQualification(
            run_id=run_id,
            target_id="t1",
            url=url,
            title="t",
            category="adverse_media",
            relevance="high",
            confidence=0.5,
            rationale="r",
            provider="p",
            model="m",
        )

    await persist_qualifications(
        [_row(1, "https://example.com/b"), _row(1, "https://example.com/a"), _row(2, "x")]
    )

    rows = await load_run_qualifications(1)

    assert [r.url for r in rows] == ["https://example.com/a", "https://example.com/b"]
