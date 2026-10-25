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
    # The identifiers live in the annex; the delta section lists values.
    assert "domain-name--1" in text
    assert "ipv4-addr--1" in text
    new_section = text.split("## Novedades desde la corrida anterior", 1)[1].split("## Errores", 1)[
        0
    ]
    assert "- dominio: `example.com`" in new_section
    assert "1.2.3.4" not in new_section
    assert "domain-name--1" not in new_section


@pytest.mark.asyncio
async def test_report_reads_executive_part_first_and_annex_last(tmp_path: Path) -> None:
    """Synthesis, evidence and news come before the technical annex, and the
    document data block closes the report."""
    from orchestrator.models import Finding

    finding = Finding(
        target_id="alpha",
        run_id=101,
        summary="Resumen de prueba.",
        new_since_last_run=["Dominio nuevo example.com"],
        risk_level="high",
        risk_justification="Motivo de prueba.",
        suggested_pivots=["Registro mercantil"],
        provider="nebius",
        model="nvidia/test-model",
    )
    text = (
        await generate_report(_sample_report_data(), report_dir=str(tmp_path), finding=finding)
    ).read_text(encoding="utf-8")

    order = [
        text.index("## Síntesis"),
        text.index("## Evidencia calificada"),
        text.index("## Novedades desde la corrida anterior"),
        text.index("## Errores"),
        text.index("## Anexo técnico"),
        text.index("### Estado por recolector"),
        text.index("### Inventario completo"),
        text.index("### Relaciones"),
        text.index("## Datos del documento"),
    ]
    assert order == sorted(order)
    # Labels for the reader, identifiers for the record.
    assert "- **Estado:** exitosa (`success`)" in text
    assert "**Riesgo**: alto (`high`) — Motivo de prueba." in text
    assert "**Novedades desde la corrida anterior**:\n- Dominio nuevo example.com" in text
    assert "**Pivotes sugeridos**:\n- Registro mercantil" in text
    assert "| openosint | correcto | 2 |" in text
    assert "**dominio** (`domain-name`)" in text
    assert "- resuelve a: `example.com` -> `1.2.3.4` (domain-name--1 -> ipv4-addr--1)" in text
    assert "- **Generado por:** OSINT Orchestrator " in text
    assert "- **Evaluación automática:** nebius · nvidia/test-model" in text
    assert "no constituyen dictamen" in text.lower() or "No constituyen dictamen" in text


@pytest.mark.asyncio
async def test_report_dates_follow_the_configured_timezone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The local stamp is what a file is dated by; the UTC instant stays
    beside it. An unknown zone falls back to UTC instead of failing."""
    monkeypatch.setattr("orchestrator.reports.settings.orchestrator_timezone", "America/Montevideo")
    text = (await generate_report(_sample_report_data(), report_dir=str(tmp_path))).read_text(
        encoding="utf-8"
    )
    assert "- **Inicio:** 08/09/2026 07:00 -03 (`2026-09-08T10:00:00Z`)" in text

    monkeypatch.setattr("orchestrator.reports.settings.orchestrator_timezone", "Mars/Olympus")
    text = (
        await generate_report(_sample_report_data(target_id="beta"), report_dir=str(tmp_path))
    ).read_text(encoding="utf-8")
    assert "- **Inicio:** 08/09/2026 10:00 UTC (`2026-09-08T10:00:00Z`)" in text


@pytest.mark.asyncio
async def test_qualified_evidence_shows_labels_and_percent(tmp_path: Path) -> None:
    data = _sample_report_data().model_copy(
        update={
            "evidence": [
                {
                    "category": "adverse_media",
                    "relevance": "high",
                    "confidence": 0.86,
                    "title": "Investigation",
                    "url": "https://news.example/x",
                    "rationale": "Trata de la entidad.",
                }
            ]
        }
    )
    text = (await generate_report(data, report_dir=str(tmp_path))).read_text(encoding="utf-8")
    assert "| prensa adversa | alto | 86 % | [Investigation](https://news.example/x) |" in text
    assert "las asigna el modelo clasificador" in text


@pytest.mark.asyncio
async def test_report_without_finding_says_so_and_points_to_the_evidence(tmp_path: Path) -> None:
    text = (
        await generate_report(_sample_report_data(), report_dir=str(tmp_path), finding=None)
    ).read_text(encoding="utf-8")
    assert "Esta corrida no incluye evaluación automática de riesgo" in text
    assert "- **Evaluación automática:** sin evaluación automática" in text


@pytest.mark.asyncio
async def test_daily_index_shows_labels(tmp_path: Path) -> None:
    from orchestrator.models import Finding

    finding = Finding(target_id="alpha", run_id=101, summary="s", risk_level="high")
    await generate_report(_sample_report_data(), report_dir=str(tmp_path), finding=finding)
    text = (tmp_path / "2026-09-08" / "index.md").read_text(encoding="utf-8")
    assert "| alpha | exitosa | 1 | alto |" in text


@pytest.mark.asyncio
async def test_bundle_output_is_byte_identical_for_same_data(tmp_path: Path) -> None:
    data = _sample_report_data()
    first = await generate_report(data, report_dir=str(tmp_path))
    first_bytes = (first.parent / "bundle.stix.json").read_bytes()

    second = await generate_report(data, report_dir=str(tmp_path))
    second_bytes = (second.parent / "bundle.stix.json").read_bytes()
    assert first_bytes == second_bytes


@pytest.mark.asyncio
async def test_two_runs_of_a_target_on_the_same_day_keep_their_own_artefacts(
    tmp_path: Path,
) -> None:
    first_data = _sample_report_data()
    second_data = first_data.model_copy(update={"run_id": first_data.run_id + 1})

    first = await generate_report(first_data, report_dir=str(tmp_path))
    first_text = first.read_text(encoding="utf-8")
    second = await generate_report(second_data, report_dir=str(tmp_path))

    assert first.parent.name == f"run-{first_data.run_id}"
    assert second.parent.name == f"run-{second_data.run_id}"
    assert first.parent.parent == second.parent.parent  # same <date>/<target>
    # The first run's report is still the one it wrote.
    assert first.read_text(encoding="utf-8") == first_text
    assert (first.parent / "bundle.stix.json").exists()
    assert (second.parent / "bundle.stix.json").exists()


@pytest.mark.asyncio
async def test_daily_index_links_the_latest_run_directory(tmp_path: Path) -> None:
    data = _sample_report_data(target_id="alpha")
    await generate_report(data, report_dir=str(tmp_path))
    later = data.model_copy(update={"run_id": data.run_id + 5})
    await generate_report(later, report_dir=str(tmp_path))

    text = (tmp_path / "2026-09-08" / "index.md").read_text(encoding="utf-8")
    assert f"(./alpha/run-{later.run_id}/report.md)" in text
    assert f"run-{data.run_id}/" not in text


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

        # daily_reports/<date>/<target>/run-<id>/report.md
        assert naive_report.parent.parent.parent.name == "2026-09-08"
        assert aware_report.parent.parent.parent.name == "2026-09-08"
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
