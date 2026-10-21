"""The showcase replay: the recordings in orchestrator/showcase_data/ go through the real pipeline.

The recordings shipped with the repository are the fixture: a regression here
means the sample a reader sees first is broken.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.alert_cases as alert_cases_module
import orchestrator.pipeline as pipeline_module
import orchestrator.run_control as run_control_module
import orchestrator.showcase as showcase_module
import orchestrator.synthesizer as synthesizer_module
import orchestrator.synthesizer.qualify as qualify_module
from orchestrator.config import settings
from orchestrator.evidence import verify_target_chain
from orchestrator.models import (
    AlertCase,
    EvidenceQualification,
    FindingRecord,
    Run,
    RunObservable,
    RunStatus,
    Target,
)
from orchestrator.showcase import (
    MODEL,
    PROVIDER,
    Recording,
    ShowcaseLLMClient,
    load_recording,
    recordings_in,
    replay,
    replay_all,
)
from orchestrator.targets import load_targets

REPO = Path(__file__).resolve().parents[2]
SEED_DIR = REPO / "orchestrator" / "showcase_data"
KEY = "test-key"


def _showcase_target(report_dir: Path) -> Target:
    targets, errors = load_targets(str(REPO / "targets.example.yaml"))
    assert not errors
    target = next(t for t in targets if t.id == "showcase-example")
    return target.model_copy(update={"report_dir": str(report_dir)})


@pytest.fixture
def db(monkeypatch: pytest.MonkeyPatch):
    """One in-memory database shared by every module the pipeline writes through."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    for module in (
        pipeline_module,
        run_control_module,
        qualify_module,
        synthesizer_module,
        alert_cases_module,
    ):
        monkeypatch.setattr(module, "get_session", _session)
    monkeypatch.setattr(settings, "opencti_enabled", False)
    monkeypatch.setattr(settings, "orchestrator_secret_key", KEY)
    monkeypatch.setattr(settings, "orchestrator_language", "en")
    return _session, engine


async def _create_all(engine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


# ─── The shipped recordings ──────────────────────────────────────────────────


def test_shipped_recordings_load_and_target_block_matches() -> None:
    paths = recordings_in(SEED_DIR)
    assert [p.name for p in paths] == ["run-1.json", "run-2.json"]
    recordings = [load_recording(p) for p in paths]
    assert {r.target_id for r in recordings} == {"showcase-example"}
    target = _showcase_target(Path("daily_reports"))
    assert target.enabled is False, "the sample target must never run live"
    assert target.collectors.tavily.enabled and not target.collectors.spiderfoot.enabled
    for recording in recordings:
        assert set(recording.finding) == {"en", "es"}
        urls = {item.url for block in recording.collectors for item in block.evidence}
        assert {q.url for q in recording.qualifications} == urls
        for q in recording.qualifications:
            assert set(q.rationale) == {"en", "es"}


def test_recordings_use_reserved_names_only() -> None:
    """The sample must not point at anything real (RFC 2606 names, TEST-NET addresses)."""
    for path in recordings_in(SEED_DIR):
        recording = load_recording(path)
        for block in recording.collectors:
            for obs in block.observables:
                if obs.type == "ipv4-addr":
                    assert obs.value.startswith("203.0.113."), obs.value
                elif obs.type == "url":
                    assert ".example/" in obs.value, obs.value
                else:
                    assert obs.value.endswith(".example"), obs.value


def test_load_recording_rejects_invalid_files(tmp_path: Path) -> None:
    bad_json = tmp_path / "run-1.json"
    bad_json.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_recording(bad_json)
    wrong_shape = tmp_path / "run-2.json"
    wrong_shape.write_text(json.dumps({"showcase_version": 2}), encoding="utf-8")
    with pytest.raises(ValueError, match="not a showcase recording"):
        load_recording(wrong_shape)
    with pytest.raises(ValueError, match="cannot read"):
        load_recording(tmp_path / "missing.json")


# ─── The scripted LLM client ─────────────────────────────────────────────────


def _recording() -> Recording:
    return load_recording(SEED_DIR / "run-1.json")


@pytest.mark.asyncio
async def test_scripted_client_answers_qualification_by_batch_index() -> None:
    client = ShowcaseLLMClient(_recording(), language="es")
    assert client.provider == PROVIDER
    assert client.model_for_route("fast") == MODEL
    known = "https://registry.example/companies/MRH-2041-7"
    prompt = "\n".join(
        [
            "# Evidence qualification request",
            "===== BEGIN UNTRUSTED DATA =====",
            "- index: 0",
            "  title: unknown page",
            "  url: https://nowhere.example/not-recorded",
            "- index: 1",
            "  title: record",
            f"  url: {known}",
            "===== END UNTRUSTED DATA =====",
        ]
    )
    raw = await client.complete("system", prompt, timeout=1, model_route="fast")
    items = json.loads(raw)["items"]
    assert [item["index"] for item in items] == [1]
    assert items[0]["category"] == "corporate_profile"
    assert items[0]["rationale"].startswith("Registro oficial")


@pytest.mark.asyncio
async def test_scripted_client_returns_finding_in_target_language_with_fallback() -> None:
    recording = _recording()
    es = ShowcaseLLMClient(recording, language="es")
    raw = await es.complete("system", "user", timeout=1, model_route="reasoning")
    assert json.loads(raw)["summary"].startswith("Ejecución de referencia")

    only_en = recording.model_copy(update={"finding": {"en": recording.finding["en"]}})
    fallback = ShowcaseLLMClient(only_en, language="es")
    raw = await fallback.complete("system", "user", timeout=1, model_route="reasoning")
    assert json.loads(raw)["risk_level"] == "medium"


# ─── Replay through the pipeline ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_replay_seals_chains_and_opens_cases(db, tmp_path: Path) -> None:
    session_ctx, engine = db
    await _create_all(engine)
    target = _showcase_target(tmp_path)

    run_ids = [await replay(load_recording(p), target) for p in recordings_in(SEED_DIR)]
    assert run_ids == [1, 2]

    async with session_ctx() as session:
        runs = (await session.exec(select(Run).order_by(Run.id))).all()
        assert [r.status for r in runs] == [RunStatus.SUCCESS, RunStatus.SUCCESS]
        assert [r.collectors_run for r in runs] == ["openosint,tavily"] * 2
        assert [r.new_observables for r in runs] == [9, 4]
        assert all(r.manifest_sha256 and r.error is None for r in runs)

        findings = (await session.exec(select(FindingRecord).order_by(FindingRecord.run_id))).all()
        assert [f.risk_level for f in findings] == ["medium", "high"]
        assert {(f.provider, f.model) for f in findings} == {(PROVIDER, MODEL)}
        assert findings[1].summary.startswith("Second run of the fictitious sample entity")
        assert len(json.loads(findings[1].new_since_last_run)) == 3

        rows = (await session.exec(select(EvidenceQualification))).all()
        assert sorted(r.run_id for r in rows) == [1] * 5 + [2] * 7
        assert {(r.provider, r.model) for r in rows} == {(PROVIDER, MODEL)}
        second = {r.url: r for r in rows if r.run_id == 2}
        assert second["https://watchlists.example/consolidated/entries/MRH-0931"].category == (
            "sanctions"
        )

        delta = (
            await session.exec(
                select(RunObservable).where(RunObservable.run_id == 2).where(RunObservable.is_new)
            )
        ).all()
        assert {o.value for o in delta} == {
            "meridian-ridge-trading.example",
            "compliance@meridian-ridge.example",
            "https://news.example/investigations/meridian-ridge-shell-companies",
            "https://watchlists.example/consolidated/entries/MRH-0931",
        }

        cases = (await session.exec(select(AlertCase).order_by(AlertCase.run_id))).all()
        assert [(c.risk_level, c.new_observable_count, c.state) for c in cases] == [
            ("medium", 9, "open"),
            ("high", 4, "open"),
        ]

        chain = await verify_target_chain(target_id=target.id, secret_key=KEY, session=session)
        assert chain["ok"] is True, chain
        assert (chain["checked"], chain["unsealed"]) == (2, 0)

    run_dir = Path(runs[1].report_path).parent
    assert {p.name for p in run_dir.iterdir()} >= {
        "report.md",
        "bundle.stix.json",
        "delta.json",
        "manifest.json",
        "qualified_evidence.json",
    }
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "## New since previous run" in report
    assert "meridian-ridge-trading.example" in report
    qualified = json.loads((run_dir / "qualified_evidence.json").read_text(encoding="utf-8"))
    assert len(qualified) == 7


@pytest.mark.asyncio
async def test_replay_refuses_when_a_run_is_pending(db, tmp_path: Path) -> None:
    session_ctx, engine = db
    await _create_all(engine)
    target = _showcase_target(tmp_path)
    assert await run_control_module.create_pending_run(target.id) == 1
    assert await replay(load_recording(SEED_DIR / "run-1.json"), target) is None


# ─── The command's preconditions ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_replay_all_refuses_opencti_ingest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "opencti_enabled", True)
    assert await replay_all(SEED_DIR, targets_file=str(REPO / "targets.example.yaml")) == 1


@pytest.mark.asyncio
async def test_replay_all_reports_missing_recordings_and_target(
    db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert await replay_all(tmp_path, targets_file=str(REPO / "targets.example.yaml")) == 1

    targets_without_sample = tmp_path / "targets.yaml"
    targets_without_sample.write_text(
        "targets:\n  - id: other\n    fqdn: example.com\n    authorization: a\n    purpose: p\n",
        encoding="utf-8",
    )
    created: list[str] = []

    async def _no_migrations() -> None:
        created.append("called")

    monkeypatch.setattr(showcase_module, "create_db_and_tables", _no_migrations)
    assert await replay_all(SEED_DIR, targets_file=str(targets_without_sample)) == 1
    assert created == [], "the database is not touched before the target check passes"


@pytest.mark.asyncio
async def test_replay_all_runs_every_recording(
    db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_ctx, engine = db
    await _create_all(engine)

    async def _no_migrations() -> None:
        return None

    monkeypatch.setattr(showcase_module, "create_db_and_tables", _no_migrations)
    targets_file = tmp_path / "targets.yaml"
    block = _showcase_target(tmp_path / "reports").model_dump(mode="json")
    targets_file.write_text(json.dumps({"targets": [block]}), encoding="utf-8")

    assert await replay_all(SEED_DIR, targets_file=str(targets_file)) == 0
    async with session_ctx() as session:
        assert len((await session.exec(select(Run))).all()) == 2
