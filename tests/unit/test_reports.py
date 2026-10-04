from __future__ import annotations

import builtins
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from orchestrator.reports import (
    CollectorReportResult,
    ReportObservable,
    RunReportData,
    generate_report,
)


def _sample_report_data(*, target_id: str = "alpha", status: str = "success") -> RunReportData:
    started = datetime(2026, 9, 8, 10, 0, tzinfo=UTC)
    finished = datetime(2026, 9, 8, 10, 5, tzinfo=UTC)
    return RunReportData(
        target_id=target_id,
        target_fqdn=f"{target_id}.example.com",
        authorization="self-owned",
        purpose="monitoring",
        run_id=101 if target_id == "alpha" else 102,
        run_status=status,
        run_started_at=started,
        run_finished_at=finished,
        collector_results=[
            CollectorReportResult(
                collector="openosint",
                success=status != "failed",
                error="collector failed" if status == "failed" else None,
                observable_count=2 if status != "failed" else 0,
            )
        ],
        bundles=[
            {
                "type": "bundle",
                "objects": [
                    {"type": "domain-name", "id": "domain-name--1", "value": "example.com"},
                    {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.2.3.4"},
                    {
                        "type": "relationship",
                        "id": "relationship--1",
                        "relationship_type": "resolves-to",
                        "source_ref": "domain-name--1",
                        "target_ref": "ipv4-addr--1",
                    },
                ],
            }
        ]
        if status != "failed"
        else [],
        observables=[
            ReportObservable(
                stix_id="domain-name--1",
                stix_type="domain-name",
                value="example.com",
                is_new=True,
            ),
            ReportObservable(
                stix_id="ipv4-addr--1",
                stix_type="ipv4-addr",
                value="1.2.3.4",
                is_new=False,
            ),
        ]
        if status != "failed"
        else [],
        errors=["collector failed"] if status == "failed" else [],
        language=None,
    )


@pytest.mark.asyncio
async def test_generate_report_writes_markdown_bundle_and_delta(tmp_path: Path) -> None:
    data = _sample_report_data()
    report_path = await generate_report(data, report_dir=str(tmp_path))
    run_dir = report_path.parent

    assert report_path.exists()
    assert (run_dir / "bundle.stix.json").exists()
    assert (run_dir / "delta.json").exists()


@pytest.mark.asyncio
async def test_pdf_is_optional_when_fpdf2_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):  # noqa: ANN001
        if name == "fpdf":
            raise ImportError("blocked in test")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    data = _sample_report_data()
    report_path = await generate_report(data, report_dir=str(tmp_path))
    assert report_path.exists()
    assert not (report_path.parent / "report.pdf").exists()
    assert (report_path.parent / "bundle.stix.json").exists()
    assert (report_path.parent / "delta.json").exists()


@pytest.mark.asyncio
async def test_markdown_language_default_es_and_en_override(tmp_path: Path) -> None:
    es_report = await generate_report(_sample_report_data(), report_dir=str(tmp_path))
    es_text = es_report.read_text(encoding="utf-8")
    assert "# Reporte diario OSINT" in es_text

    en_report = await generate_report(
        _sample_report_data(target_id="beta"),
        report_dir=str(tmp_path),
        language="en",
    )
    en_text = en_report.read_text(encoding="utf-8")
    assert "# Daily OSINT report" in en_text


@pytest.mark.asyncio
async def test_new_section_only_contains_is_new_true(tmp_path: Path) -> None:
    data = _sample_report_data()
    report = await generate_report(data, report_dir=str(tmp_path))
    text = report.read_text(encoding="utf-8")
    assert "domain-name--1" in text
    assert "ipv4-addr--1" in text
    new_section = text.split("## Nuevo desde la última corrida", 1)[1].split(
        "## Inventario completo", 1
    )[0]
    assert "domain-name--1" in new_section
    assert "ipv4-addr--1" not in new_section


@pytest.mark.asyncio
async def test_bundle_output_is_byte_identical_for_same_data(tmp_path: Path) -> None:
    data = _sample_report_data()
    first = await generate_report(data, report_dir=str(tmp_path))
    first_bytes = (first.parent / "bundle.stix.json").read_bytes()

    second = await generate_report(data, report_dir=str(tmp_path))
    second_bytes = (second.parent / "bundle.stix.json").read_bytes()
    assert first_bytes == second_bytes


@pytest.mark.asyncio
async def test_daily_index_accumulates_targets(tmp_path: Path) -> None:
    await generate_report(_sample_report_data(target_id="alpha"), report_dir=str(tmp_path))
    await generate_report(_sample_report_data(target_id="beta"), report_dir=str(tmp_path))

    index_path = tmp_path / "2026-09-08" / "index.md"
    text = index_path.read_text(encoding="utf-8")
    assert "| alpha |" in text
    assert "| beta |" in text


@pytest.mark.asyncio
async def test_failed_run_without_observables_still_generates_report(tmp_path: Path) -> None:
    report = await generate_report(
        _sample_report_data(target_id="failed-target", status="failed"),
        report_dir=str(tmp_path),
    )
    text = report.read_text(encoding="utf-8")
    delta = json.loads((report.parent / "delta.json").read_text(encoding="utf-8"))

    assert "## Errores" in text
    assert "collector failed" in text
    assert delta == []


@pytest.mark.asyncio
async def test_naive_and_aware_utc_dates_match_under_non_utc_host_tz(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    previous_tz = os.environ.get("TZ")
    monkeypatch.setenv("TZ", "America/Montevideo")
    time.tzset()
    try:
        naive_data = _sample_report_data(target_id="naive")
        naive_data.run_started_at = datetime(2026, 9, 8, 23, 30)
        naive_data.run_finished_at = datetime(2026, 9, 8, 23, 35)

        aware_data = _sample_report_data(target_id="aware")
        aware_data.run_started_at = datetime(2026, 9, 8, 23, 30, tzinfo=UTC)
        aware_data.run_finished_at = datetime(2026, 9, 8, 23, 35, tzinfo=UTC)

        naive_report = await generate_report(naive_data, report_dir=str(tmp_path))
        aware_report = await generate_report(aware_data, report_dir=str(tmp_path))

        assert naive_report.parent.parent.name == "2026-09-08"
        assert aware_report.parent.parent.name == "2026-09-08"
    finally:
        if previous_tz is None:
            monkeypatch.delenv("TZ", raising=False)
        else:
            monkeypatch.setenv("TZ", previous_tz)
        time.tzset()


async def test_report_renders_when_synthesis_failed(tmp_path: Path) -> None:
    """
    The "failed" synthesis status used to render the catalogue key that carries
    an {error} placeholder with no error to give it — KeyError — and the
    pipeline swallowed it, so any LLM failure meant no report at all.
    """
    from orchestrator.i18n import t

    report_path = await generate_report(
        _sample_report_data(), report_dir=str(tmp_path), finding=None, synthesis_status="failed"
    )
    text = report_path.read_text(encoding="utf-8")
    assert any(t("synthesis_unavailable", language=lang) in text for lang in ("es", "en"))
