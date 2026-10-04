"""
ADR-007: signed per-run evidence manifests chained per target.

Runs go through the real pipeline (collectors, synthesis and the OpenCTI sink
stubbed) so the manifests under test are the ones production writes; the
verifier then reads them back through the same session.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.pipeline as pipeline_module
from orchestrator.config import settings
from orchestrator.evidence import (
    build_manifest,
    canonical_json,
    sha256_file,
    verify_target_chain,
)
from orchestrator.models import (
    CollectorName,
    CollectorResult,
    Observable,
    Run,
    RunStatus,
    Target,
)
from orchestrator.pipeline import _artefacts_for_manifest, run_target_pipeline

KEY = "test-key"


class _FakeCollector:
    name = CollectorName.OPENOSINT

    def __init__(self, target: Target) -> None:
        self.target = target

    async def collect(self) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            target_fqdn=self.target.fqdn,
            observables=[Observable(type="domain-name", value=self.target.fqdn)],
            success=True,
        )


class _FakeSink:
    async def ingest_async(self, bundle, **_: object) -> None:
        return None


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    async def _no_synthesize(*args, **kwargs):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "get_session", _session)
    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_FakeCollector(t)])
    monkeypatch.setattr(pipeline_module, "synthesize", _no_synthesize)
    monkeypatch.setattr(pipeline_module, "OpenCTISink", _FakeSink)
    monkeypatch.setattr(settings, "orchestrator_secret_key", KEY)

    target = Target(
        id="chain-target",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        report_dir=str(tmp_path),
    )

    class _Harness:
        session = staticmethod(_session)

        async def setup(self) -> None:
            async with engine.begin() as conn:
                await conn.run_sync(SQLModel.metadata.create_all)

        async def run(self, minute: int) -> Run:
            async with _session() as session:
                run = Run(
                    target_id=target.id,
                    started_at=datetime(2026, 9, 8, 12, minute, tzinfo=UTC),
                    status=RunStatus.PENDING,
                )
                session.add(run)
                await session.commit()
                await session.refresh(run)
                run_id = run.id
            await run_target_pipeline(target, run_id)
            async with _session() as session:
                return await session.get(Run, run_id)

        async def verify(self, key: str = KEY) -> dict:
            async with _session() as session:
                return await verify_target_chain(
                    target_id=target.id, secret_key=key, session=session
                )

        async def delete_row(self, run_id: int) -> None:
            async with _session() as session:
                await session.delete(await session.get(Run, run_id))
                await session.commit()

    return _Harness()


def _manifest(run: Run) -> dict:
    return json.loads((Path(run.report_path).parent / "manifest.json").read_text(encoding="utf-8"))


# ─── Manifest construction ────────────────────────────────────────────────────


def test_manifest_is_deterministic_for_fixed_inputs() -> None:
    kwargs = {
        "run_id": 7,
        "target_id": "t",
        "status": "success",
        "collectors_run": ["openosint"],
        "artefacts": {"report.md": "sha256:aa", "bundle.stix.json": "sha256:bb"},
        "previous_manifest_sha256": None,
        "secret_key": KEY,
    }
    naive = build_manifest(
        started_at=datetime(2026, 9, 8, 12, 0),
        finished_at=datetime(2026, 9, 8, 12, 5),
        **kwargs,
    )
    aware = build_manifest(
        started_at=datetime(2026, 9, 8, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 9, 8, 12, 5, tzinfo=UTC),
        **kwargs,
    )
    # A naive datetime (SQLite) is UTC, whatever the host's time zone.
    assert canonical_json(naive) == canonical_json(aware)
    assert naive["started_at"] == "2026-09-08T12:00:00+00:00"
    assert list(naive["artefacts"]) == ["bundle.stix.json", "report.md"]


def test_pdf_absent_means_key_absent_not_null(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    (run_dir / "report.md").write_text("r", encoding="utf-8")
    (run_dir / "manifest.json").write_text("{}", encoding="utf-8")

    artefacts = _artefacts_for_manifest(str(run_dir / "report.md"))

    assert "report.pdf" not in artefacts
    assert "manifest.json" not in artefacts
    assert artefacts["report.md"] == sha256_file(run_dir / "report.md")


# ─── Pipeline → verifier round trip ───────────────────────────────────────────


async def test_pipeline_runs_are_sealed_chained_and_verify_ok(harness) -> None:
    await harness.setup()
    first = await harness.run(0)
    second = await harness.run(1)

    assert first.manifest_sha256 and second.manifest_sha256
    assert Path(first.report_path).parent != Path(second.report_path).parent
    assert _manifest(first)["previous_manifest_sha256"] is None
    assert _manifest(second)["previous_manifest_sha256"] == first.manifest_sha256
    assert sha256_file(Path(second.report_path).parent / "manifest.json") == second.manifest_sha256

    result = await harness.verify()
    assert result == {
        "ok": True,
        "checked": 2,
        "unsealed": 0,
        "first_broken_run_id": None,
        "reason": None,
        "detail": None,
        "anchor_run_id": None,
        "anchor_previous_manifest_sha256": None,
    }


async def test_target_without_runs_verifies_ok_with_checked_0(harness) -> None:
    await harness.setup()
    result = await harness.verify()
    assert result["ok"] is True
    assert result["checked"] == 0


# ─── Tampering ────────────────────────────────────────────────────────────────


async def test_one_byte_change_in_report_breaks_at_that_run_with_artefact_hash(harness) -> None:
    await harness.setup()
    first = await harness.run(0)
    await harness.run(1)
    report = Path(first.report_path)
    report.write_bytes(report.read_bytes() + b" ")

    result = await harness.verify()

    assert result["ok"] is False
    assert result["first_broken_run_id"] == first.id
    assert result["reason"] == "artefact_hash"
    assert result["detail"] == "report.md"


async def test_deleted_artefact_reports_artefact_missing(harness) -> None:
    await harness.setup()
    run = await harness.run(0)
    (Path(run.report_path).parent / "delta.json").unlink()

    result = await harness.verify()

    assert (result["reason"], result["detail"]) == ("artefact_missing", "delta.json")


async def test_edited_manifest_reports_signature(harness) -> None:
    await harness.setup()
    run = await harness.run(0)
    manifest_path = Path(run.report_path).parent / "manifest.json"
    edited = _manifest(run) | {"status": "failed"}
    manifest_path.write_text(canonical_json(edited), encoding="utf-8")

    result = await harness.verify()

    assert (result["first_broken_run_id"], result["reason"]) == (run.id, "signature")


async def test_different_key_reports_signature_key(harness) -> None:
    await harness.setup()
    run = await harness.run(0)

    result = await harness.verify(key="another-key")

    assert (result["first_broken_run_id"], result["reason"]) == (run.id, "signature_key")


async def test_removed_middle_run_breaks_the_next_link(harness) -> None:
    await harness.setup()
    await harness.run(0)
    middle = await harness.run(1)
    last = await harness.run(2)
    await harness.delete_row(middle.id)

    result = await harness.verify()

    assert (result["first_broken_run_id"], result["reason"]) == (last.id, "chain_link")


async def test_retention_of_the_oldest_runs_is_not_tampering(harness) -> None:
    await harness.setup()
    oldest = await harness.run(0)
    kept = await harness.run(1)
    await harness.run(2)
    await harness.delete_row(oldest.id)  # what retention does with old rows

    result = await harness.verify()

    assert result["ok"] is True
    assert result["checked"] == 2
    assert result["anchor_run_id"] == kept.id
    assert result["anchor_previous_manifest_sha256"] == oldest.manifest_sha256


# ─── Unsealed runs and versions ───────────────────────────────────────────────


async def test_run_failing_before_manifest_is_unsealed_and_next_run_chains_past_it(
    harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    await harness.setup()
    first = await harness.run(0)

    def _disk_full(**_: object) -> str:
        raise OSError("No space left on device")

    with monkeypatch.context() as patch:
        patch.setattr(pipeline_module, "write_manifest_file", _disk_full)
        unsealed = await harness.run(1)
    last = await harness.run(2)

    assert unsealed.status == RunStatus.SUCCESS  # the final status survived
    assert unsealed.manifest_sha256 is None
    assert (Path(unsealed.report_path).parent / "report.md").exists()
    assert _manifest(last)["previous_manifest_sha256"] == first.manifest_sha256

    result = await harness.verify()
    assert (result["ok"], result["checked"], result["unsealed"]) == (True, 2, 1)


async def test_manifest_version_99_reports_unsupported_version(harness) -> None:
    await harness.setup()
    run = await harness.run(0)
    manifest_path = Path(run.report_path).parent / "manifest.json"
    manifest_path.write_text(canonical_json(_manifest(run) | {"manifest_version": 99}), "utf-8")
    # A future verifier wrote it: the stored hash matches the file on disk.
    async with harness.session() as session:
        row = await session.get(Run, run.id)
        row.manifest_sha256 = sha256_file(manifest_path)
        session.add(row)
        await session.commit()

    result = await harness.verify()

    assert (result["reason"], result["detail"]) == ("unsupported_version", "99")


@pytest.mark.parametrize(
    ("key", "warns"), [("", True), ("insecure-dev-key", True), ("x" * 64, False)]
)
def test_startup_warns_on_an_empty_or_default_signing_key(
    key: str, warns: bool, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from orchestrator.auth import log_secret_key_status  # noqa: PLC0415

    monkeypatch.setattr(settings, "orchestrator_secret_key", key)
    with caplog.at_level("WARNING", logger="orchestrator.auth"):
        log_secret_key_status()

    records = [
        r for r in caplog.records if getattr(r, "setting", None) == "ORCHESTRATOR_SECRET_KEY"
    ]
    assert bool(records) is warns
