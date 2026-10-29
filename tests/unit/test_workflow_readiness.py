"""User-facing readiness regressions: qualification failures and readable PDFs."""

import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from sqlmodel import SQLModel, select

import orchestrator.pipeline as pipeline
import orchestrator.synthesizer as synthesis
import orchestrator.synthesizer.qualify as qualification
from orchestrator.config import settings
from orchestrator.models import AlertsConfig, Run, RunStatus
from orchestrator.reports import _write_optional_pdf
from tests.unit.test_evidence_qualification import (
    _engine,
    _session_factory,
    _SimpleCollector,
    _target,
)


@pytest.mark.parametrize("mode", ["timeout", "missing"])
async def test_incomplete_qualification_survives_pipeline_and_degrades_result(
    monkeypatch, tmp_path, mode
):
    engine = _engine()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    sessions = _session_factory(engine)
    for module in (pipeline, synthesis, qualification):
        monkeypatch.setattr(module, "get_session", sessions)
    monkeypatch.setattr(settings, "opencti_enabled", False)
    monkeypatch.setattr(settings, "llm_provider", "openai")
    target = _target().model_copy(
        update={"report_dir": str(tmp_path), "alerts": AlertsConfig(enabled=False)}
    )

    class Client:
        provider = "test"

        def model_for_route(self, route):
            return "test-model"

        async def complete(self, *_args, **kwargs):
            if kwargs.get("model_route") == "fast":
                if mode == "timeout":
                    raise TimeoutError("test qualification timeout")
                return '{"items": []}'
            return json.dumps(
                {
                    "summary": "Test",
                    "risk_level": "low",
                    "risk_justification": "Test",
                    "new_since_last_run": [],
                    "suggested_pivots": [],
                }
            )

    async with sessions() as session:
        run = Run(target_id=target.id)
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id
    await pipeline.run_target_pipeline(
        target, run_id, collectors=[_SimpleCollector(target)], llm_client=Client()
    )
    async with sessions() as session:
        run = (await session.exec(select(Run).where(Run.id == run_id))).one()
        assert run.status == RunStatus.PARTIAL
        assert run.qualification_status == "incomplete"
        assert run.error and "qualification:" in run.error
        if mode == "timeout":
            assert "test qualification timeout" in run.error
        assert run.evidence_collected == 1 and run.evidence_qualified == 0
        assert "qualification:" in Path(run.report_path).read_text()
        assert run.report_status == "ok" and run.integrity_status == "ok"


def test_pdf_keeps_unicode_content_and_all_words_inside_pages(tmp_path):
    if not shutil.which("pdftotext"):
        pytest.skip("PDF text/bounding-box validation requires Poppler pdftotext")
    path = tmp_path / "report.pdf"
    text = "# Informe — revisión\n\nAutorización: Pérez € 42\n" + "\n".join(
        f"Cliente-{i:03d} evidencia completa " + "texto verificable " * 15 for i in range(65)
    )
    _write_optional_pdf(path, text)
    output = subprocess.check_output(["pdftotext", str(path), "-"], text=True)
    # Accents survive as themselves; the glyphs outside Latin-1 that the core
    # font cannot draw are transliterated by the documented table in
    # reports/pdf.py rather than dropped, and the dashes with them.
    assert "Autorización: Pérez EUR 42" in output
    assert "Informe - revisión" in output
    for i in range(65):
        assert f"Cliente-{i:03d}" in output
    bbox = ET.fromstring(subprocess.check_output(["pdftotext", "-bbox", str(path), "-"]))
    pages = bbox.findall(".//{http://www.w3.org/1999/xhtml}page")
    assert len(pages) > 1
    for page in pages:
        for word in page:
            assert (
                0
                < float(word.attrib["xMin"])
                < float(word.attrib["xMax"])
                < float(page.attrib["width"])
            )
            assert (
                0
                < float(word.attrib["yMin"])
                < float(word.attrib["yMax"])
                < float(page.attrib["height"])
            )
