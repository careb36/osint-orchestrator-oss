"""Unit tests for the handoff exports: GET /runs/{id}/bundle and /runs/{id}/report.pdf."""

from __future__ import annotations

import io
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.api as api_mod
from orchestrator.api import app
from orchestrator.config import settings
from orchestrator.models import Run, RunStatus


def _make_engine():
    return create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def _session_factory(engine):
    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    return _session


async def _prepare(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, with_files: bool) -> int:
    """A sealed run whose directory holds the usual artefacts (or nothing)."""
    engine = _make_engine()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(api_mod, "get_session", session_ctx)
    monkeypatch.setattr(settings, "orchestrator_api_key", "")

    run_dir = tmp_path / "2026-10-06" / "acme.example" / "run-7"
    run_dir.mkdir(parents=True)
    if with_files:
        (run_dir / "report.md").write_text("# Report\n", encoding="utf-8")
        (run_dir / "report.pdf").write_bytes(b"%PDF-1.4 test")
        (run_dir / "bundle.stix.json").write_text("{}", encoding="utf-8")
        (run_dir / "delta.json").write_text("[]", encoding="utf-8")
        (run_dir / "manifest.json").write_text('{"manifest_version": 1}', encoding="utf-8")
        (run_dir / "nested").mkdir()  # directories are not artefacts
    async with session_ctx() as session:
        run = Run(
            target_id="acme.example",
            status=RunStatus.SUCCESS,
            report_path=str(run_dir / "report.md"),
            manifest_sha256="sha256:" + "a" * 64,
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        return int(run.id)


@pytest.mark.asyncio
async def test_bundle_zips_every_artefact_of_the_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_id = await _prepare(monkeypatch, tmp_path, with_files=True)
    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.get(f"/runs/{run_id}/bundle")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["content-disposition"] == (
        f'attachment; filename="run-{run_id}-acme.example.zip"'
    )
    assert response.headers["cache-control"] == "no-store"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert archive.namelist() == [
            "bundle.stix.json",
            "delta.json",
            "manifest.json",
            "report.md",
            "report.pdf",
        ]
        assert archive.read("report.md") == b"# Report\n"


@pytest.mark.asyncio
async def test_bundle_filename_keeps_only_safe_characters(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_id = await _prepare(monkeypatch, tmp_path, with_files=True)
    async with api_mod.get_session() as session:
        run = await session.get(Run, run_id)
        run.target_id = 'acme "corp"/é'
        session.add(run)
        await session.commit()
    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.get(f"/runs/{run_id}/bundle")
    assert response.status_code == 200
    assert response.headers["content-disposition"] == (
        f'attachment; filename="run-{run_id}-acme-corp.zip"'
    )


@pytest.mark.asyncio
async def test_bundle_is_404_without_artefacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_id = await _prepare(monkeypatch, tmp_path, with_files=False)
    with TestClient(app, raise_server_exceptions=True) as client:
        empty = client.get(f"/runs/{run_id}/bundle")
        unknown = client.get("/runs/999/bundle")
    assert empty.status_code == 404
    assert "artefactos" in empty.json()["detail"]  # operator language defaults to es
    assert unknown.status_code == 404


@pytest.mark.asyncio
async def test_pdf_report_is_served_when_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_id = await _prepare(monkeypatch, tmp_path, with_files=True)
    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.get(f"/runs/{run_id}/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content == b"%PDF-1.4 test"
    assert f'filename="run-{run_id}-report.pdf"' in response.headers["content-disposition"]


@pytest.mark.asyncio
async def test_pdf_report_is_404_when_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_id = await _prepare(monkeypatch, tmp_path, with_files=False)
    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.get(f"/runs/{run_id}/report.pdf")
    assert response.status_code == 404
    assert "PDF" in response.json()["detail"]


def test_exports_require_the_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_api_key", "test-key")
    with TestClient(app, raise_server_exceptions=True) as client:
        assert client.get("/runs/1/bundle").status_code == 401
        assert client.get("/runs/1/report.pdf").status_code == 401
