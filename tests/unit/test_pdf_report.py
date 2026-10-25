"""The PDF companion of the report: a paged, legible rendering of report.md.

The old renderer cut every line into 40-character chunks and drew half of
them past the right edge of the page; these tests pin the properties a
printable document needs: every token stays inside the page, tables keep
their header, headings and bullets are recognised, and the footer is in the
report language.
"""

from __future__ import annotations

import contextlib
import re
import zlib
from pathlib import Path

import pytest

from orchestrator.reports import generate_report
from orchestrator.reports.pdf import Block, inline_text, parse_blocks, render_pdf
from tests.unit.test_reports import _sample_report_data

LONG_URL = "https://watchlists.example/consolidated/entries/" + "x" * 200

SAMPLE_MD = "\n".join(
    [
        "# Reporte diario OSINT",
        "",
        "- **Objetivo:** `alpha` (alpha.example.com)",
        "- **Estado:** `success`",
        "",
        "## Evidencia calificada",
        "| Categoría | Relevancia | Confianza | Título | Justificación |",
        "|---|---|---:|---|---|",
        f"| sanctions | high | 0.93 | [Entrada MRH-0931]({LONG_URL}) | Lista consolidada — filial. |",
        "",
        "## Errores",
        "_Sin elementos_",
        "",
        "## Síntesis",
        "Texto de síntesis con «comillas» y una flecha → final.",
    ]
)


def _page_count(pdf_bytes: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page[^s]", pdf_bytes))


def _page_text(pdf_bytes: bytes) -> str:
    """Concatenate every (compressed) content stream as Latin-1 text."""
    chunks: list[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", pdf_bytes, re.S):
        raw = match.group(1)
        with contextlib.suppress(zlib.error):
            raw = zlib.decompress(raw)
        chunks.append(raw.decode("latin-1", "replace"))
    return "\n".join(chunks)


def _drawn_strings(pdf_bytes: bytes) -> str:
    """The literal strings fpdf2 draws with core fonts, joined in page order."""
    text = _page_text(pdf_bytes)
    pieces = re.findall(r"\((.*?)(?<!\\)\)\s*Tj", text, re.S)
    return "".join(piece.replace("\\(", "(").replace("\\)", ")") for piece in pieces)


def test_inline_text_flattens_links_emphasis_and_non_latin1() -> None:
    assert inline_text("[Título](https://e.example/x)") == "Título (https://e.example/x)"
    assert inline_text("**Riesgo**: `high` — ok") == "Riesgo: high - ok"
    assert inline_text("_Sin elementos_") == "Sin elementos"
    assert inline_text("a → b … «c»") == "a -> b ... «c»"
    # Anything outside Latin-1 and the transliteration table degrades to "?"
    # instead of aborting the render.
    assert inline_text("中文") == "??"


def test_parse_blocks_recognises_headings_bullets_tables_and_paragraphs() -> None:
    blocks = parse_blocks(SAMPLE_MD)
    kinds = [block.kind for block in blocks]
    assert kinds == ["h1", "bullet", "bullet", "h2", "table", "h2", "para", "h2", "para"]
    table = next(block for block in blocks if block.kind == "table")
    assert table.rows[0] == ["Categoría", "Relevancia", "Confianza", "Título", "Justificación"]
    assert len(table.rows) == 2  # the |---| separator line is not a row
    assert table.rows[1][3] == f"Entrada MRH-0931 ({LONG_URL})"
    assert blocks[1] == Block("bullet", "Objetivo: alpha (alpha.example.com)")


def test_render_pdf_keeps_long_tokens_on_the_page(tmp_path: Path) -> None:
    out = tmp_path / "report.pdf"
    render_pdf(out, SAMPLE_MD, "es")
    data = out.read_bytes()
    assert data.startswith(b"%PDF")
    # A short report fits on one page: the old renderer spread the same
    # content over five nearly blank pages by drawing past the right margin.
    assert _page_count(data) == 1
    drawn = _drawn_strings(data)
    assert "Reporte diario OSINT" in drawn
    assert "Lista consolidada - filial." in drawn
    # The 240-character URL is wrapped, not cut: every character is drawn.
    assert drawn.count("x") >= 200
    assert "Página 1 de 1" in drawn


def test_render_pdf_footer_follows_language(tmp_path: Path) -> None:
    out = tmp_path / "report.pdf"
    render_pdf(out, "# Daily OSINT report\n\nBody.", "en")
    assert "Page 1 of 1" in _drawn_strings(out.read_bytes())


def test_render_pdf_paginates_long_reports(tmp_path: Path) -> None:
    out = tmp_path / "report.pdf"
    bullets = "\n".join(
        f"- `domain-name` `host{i}.example` (domain-name--{i:04d})" for i in range(120)
    )
    render_pdf(out, f"# Informe\n\n## Inventario\n{bullets}\n", "es")
    data = out.read_bytes()
    assert _page_count(data) >= 2
    assert "Página 2 de" in _drawn_strings(data)


@pytest.mark.asyncio
async def test_generate_report_writes_a_pdf_in_the_report_language(tmp_path: Path) -> None:
    report_path = await generate_report(
        _sample_report_data(), report_dir=str(tmp_path), language="en"
    )
    pdf_path = report_path.parent / "report.pdf"
    assert pdf_path.exists()
    drawn = _drawn_strings(pdf_path.read_bytes())
    assert "Daily OSINT report" in drawn
    assert "Page 1 of 1" in drawn


# ─── Review follow-ups ────────────────────────────────────────────────────────

_PT_PER_MM = 72 / 25.4
_A4_WIDTH_MM = 210.0
_MARGIN_MM = 15.0


def _drawn_runs(pdf_bytes: bytes) -> list[tuple[float, float, str]]:
    """(x in mm, font size, text) for every string the PDF draws, in order."""
    runs: list[tuple[float, float, str]] = []
    size = 10.0
    for line in _page_text(pdf_bytes).splitlines():
        font = re.search(r"/F\d+ ([0-9.]+) Tf", line)
        if font:
            size = float(font.group(1))
        drawn = re.search(r"([0-9.]+) [0-9.]+ Td(?: 0 g)? \((.*)\) Tj", line)
        if drawn:
            runs.append((float(drawn.group(1)) / _PT_PER_MM, size, drawn.group(2)))
    return runs


def test_every_drawn_string_stays_between_the_margins(tmp_path: Path) -> None:
    """The property the old renderer broke: no text past the right edge.

    Each run's width is measured with the widest core face (Helvetica bold)
    at its own size, so the bound is conservative.
    """
    from fpdf import FPDF

    out = tmp_path / "report.pdf"
    render_pdf(out, SAMPLE_MD, "es")
    meter = FPDF()
    meter.set_font("Helvetica", style="B")
    runs = _drawn_runs(out.read_bytes())
    assert runs, "no text was drawn"
    for x_mm, size, text in runs:
        meter.set_font_size(size)
        right_mm = x_mm + meter.get_string_width(text.replace("\\(", "(").replace("\\)", ")"))
        assert x_mm >= _MARGIN_MM - 0.5, (x_mm, text)
        assert right_mm <= _A4_WIDTH_MM - _MARGIN_MM + 1.0, (right_mm, text)


def test_a_table_row_taller_than_a_page_is_capped_not_lost(tmp_path: Path) -> None:
    """fpdf2 refuses a row taller than the page; one 3,000-character URL or
    collector error used to cost the whole PDF. The cell is capped instead."""
    out = tmp_path / "report.pdf"
    huge = "https://e.example/" + "y" * 3000
    render_pdf(out, f"# T\n\n| a | b |\n|---|---|\n| x | {huge} |\n", "es")
    drawn = _drawn_strings(out.read_bytes())
    assert drawn.count("y") < 1000
    assert "..." in drawn


def test_rows_with_more_cells_than_the_header_and_escaped_pipes(tmp_path: Path) -> None:
    blocks = parse_blocks("| a | b |\n|:--|--:|\n| 1 | 2 | 3 |\n| x \\| y | z |\n")
    assert [block.kind for block in blocks] == ["table"]
    assert blocks[0].rows == [["a", "b"], ["1", "2", "3"], ["x | y", "z"]]
    render_pdf(tmp_path / "report.pdf", "| a | b |\n|:--|--:|\n| 1 | 2 | 3 |\n", "en")


def test_page_count_alias_does_not_rewrite_body_text(tmp_path: Path) -> None:
    out = tmp_path / "report.pdf"
    render_pdf(out, "# T\n\nPlantilla {nb} literal", "es")
    assert "Plantilla {nb} literal" in _drawn_strings(out.read_bytes())


def test_snake_case_identifiers_keep_their_underscores() -> None:
    assert inline_text("__init__") == "__init__"
    assert inline_text("_Sin elementos_") == "Sin elementos"


@pytest.mark.asyncio
async def test_render_failure_is_a_warning_and_writes_no_pdf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import orchestrator.reports.pdf as pdf_module

    def _boom(*_args, **_kwargs):
        raise RuntimeError("layout exploded")

    monkeypatch.setattr(pdf_module, "render_pdf", _boom)
    report_path = await generate_report(_sample_report_data(), report_dir=str(tmp_path))
    assert report_path.exists()
    assert not (report_path.parent / "report.pdf").exists()
    assert any("PDF generation failed" in record.getMessage() for record in caplog.records)
