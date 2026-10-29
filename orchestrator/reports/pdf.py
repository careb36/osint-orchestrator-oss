"""
PDF rendering of the Markdown report (the companion ``report.pdf``).

The report is written once as Markdown (``report.md``); this module renders
that same text as a paged document an operator can print or file, instead of
dumping the raw source. It understands the Markdown subset the report
generator emits — ATX headings, ``- `` bullets, pipe tables, paragraphs and
inline emphasis/code/links — nothing more, on purpose: a full Markdown
engine would be a new dependency, and the report's own shape is fixed.

Layout rules that matter for a legible document:

- Text always flows from the left margin to the right margin; nothing is
  ever positioned past the page edge.
- Overlong tokens (URLs, STIX ids, hashes) wrap character-wise inside the
  cell or paragraph instead of being cut.
- Tables keep their header row and wrap every cell.
- Every page carries a footer with the page number in the report language.

Fonts: the fpdf2 core Helvetica, which covers Latin-1 (all of Spanish). A
few common non-Latin-1 characters are mapped to ASCII equivalents; anything
else is replaced by ``?`` rather than aborting the render.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from orchestrator.i18n import t

_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_CODE = re.compile(r"`([^`]*)`")
_EMPHASIS = re.compile(r"\A_([^_](?:.*[^_])?)_\Z")
_HEADING = re.compile(r"\A(#{1,3})\s+(.*)\Z")
_TABLE_SEPARATOR = re.compile(r"\A\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\Z")
# A cell boundary is a pipe not escaped with a backslash.
_CELL_SPLIT = re.compile(r"(?<!\\)\|")

# Characters outside Latin-1 that the report or the model commonly produce.
_TRANSLITERATE = str.maketrans(
    {
        "—": "-",  # em dash
        "–": "-",  # en dash
        "…": "...",
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
        "•": "-",  # bullet
        "→": "->",
        "←": "<-",
        "✓": "OK",
        "€": "EUR",
        "≥": ">=",
        "≤": "<=",
        " ": " ",
    }
)

# fpdf2 replaces this alias with the page count everywhere in the document,
# so it must be a string no report or web title will ever contain ("{nb}",
# the default, could appear in a scraped title).
_PAGE_COUNT_ALIAS = "{__osint_page_count__}"

# A single table cell is capped so one row always fits on a page: fpdf2
# refuses to render a row taller than the page (a 2,000-character URL or a
# collector error dump would otherwise cost the whole PDF). The Markdown
# report keeps the full text.
_MAX_CELL_CHARS = 900

# Point sizes per block kind; body is the reference.
_SIZE = {"h1": 16.0, "h2": 13.0, "h3": 11.0, "para": 10.0, "bullet": 10.0, "table": 8.5}
_LINE_HEIGHT = {"h1": 8.0, "h2": 7.0, "h3": 6.0, "para": 5.0, "bullet": 5.0, "table": 4.5}


@dataclass
class Block:
    """One rendered unit of the report: a heading, paragraph, bullet or table."""

    kind: str  # h1 | h2 | h3 | para | bullet | table
    text: str = ""
    rows: list[list[str]] = field(default_factory=list)


def inline_text(text: str) -> str:
    """Flatten inline Markdown to plain text fit for a core PDF font.

    Links become ``text (url)`` so the source stays visible on paper; bold,
    code and whole-line emphasis markers are dropped; non-Latin-1 characters
    are transliterated or replaced.
    """
    text = _LINK.sub(lambda m: f"{m.group(1)} ({m.group(2)})", text)
    text = _BOLD.sub(r"\1", text)
    text = _CODE.sub(r"\1", text)
    text = _EMPHASIS.sub(r"\1", text.strip())
    text = text.translate(_TRANSLITERATE)
    return text.encode("latin-1", "replace").decode("latin-1")


def _split_table_row(line: str) -> list[str]:
    cells = line.strip()
    if cells.startswith("|"):
        cells = cells[1:]
    if cells.endswith("|"):
        cells = cells[:-1]
    return [inline_text(cell.strip().replace("\\|", "|")) for cell in _CELL_SPLIT.split(cells)]


def _cap(cell: str) -> str:
    return cell if len(cell) <= _MAX_CELL_CHARS else cell[: _MAX_CELL_CHARS - 3] + "..."


def parse_blocks(markdown: str) -> list[Block]:
    """Split the report Markdown into the blocks the renderer knows how to draw.

    Blank lines separate paragraphs; consecutive ``|`` lines form one table
    (the ``|---|`` separator line is dropped); every other non-blank line is a
    paragraph of its own, which matches how the generator writes them.
    """
    blocks: list[Block] = []
    table: list[list[str]] | None = None
    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if stripped.startswith("|"):
            if _TABLE_SEPARATOR.match(stripped):
                continue
            if table is None:
                table = []
            table.append(_split_table_row(stripped))
            continue
        if table is not None:
            blocks.append(Block("table", rows=table))
            table = None
        if not stripped:
            continue
        heading = _HEADING.match(stripped)
        if heading:
            blocks.append(Block(f"h{len(heading.group(1))}", inline_text(heading.group(2))))
        elif stripped.startswith("- "):
            blocks.append(Block("bullet", inline_text(stripped[2:])))
        else:
            blocks.append(Block("para", inline_text(stripped)))
    if table is not None:
        blocks.append(Block("table", rows=table))
    return blocks


def _column_widths(rows: list[list[str]], total: float) -> list[float]:
    """Share the printable width between columns by their longest cell.

    Each column gets at least an eighth of the width so a short header never
    collapses, and no column takes more than 45 %, so a long rationale leaves
    room for the title next to it.
    """
    count = max(len(row) for row in rows)
    longest = [1] * count
    for row in rows:
        for index, cell in enumerate(row):
            longest[index] = max(longest[index], min(len(cell), 80))
    weights = [max(float(length), 1.0) for length in longest]
    scale = sum(weights)
    shares = [max(0.12, min(0.45, weight / scale)) for weight in weights]
    normaliser = sum(shares)
    return [total * share / normaliser for share in shares]


def _ensure_utc(value: datetime) -> datetime:
    """SQLite returns naive datetimes; compare everything as UTC-aware."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def unrepresentable(text: str) -> list[str]:
    """Characters the core PDF font cannot draw and the table does not map.

    ``inline_text`` degrades these to ``?``. That is fine for a stray glyph,
    but a report whose entity name or authorization is entirely outside
    Latin-1 would be sealed as a document that no longer says what the
    evidence says, so the caller checks first.
    """
    mapped = text.translate(_TRANSLITERATE)
    return sorted({char for char in mapped if ord(char) > 255})


def render_pdf(
    path: Path,
    markdown: str,
    lang: str = "es",
    *,
    created_at: datetime | None = None,
) -> None:
    """Render *markdown* as ``path``; raises on any rendering problem.

    The caller decides what a failure means (the Markdown report is the
    artefact of record; the PDF is a convenience), so nothing is swallowed
    here.

    ``created_at`` stamps the document with the run's own time instead of the
    render time, so re-rendering an archived report does not move its date.

    Raises ``ValueError`` when the report carries characters the core font
    cannot draw: a document that silently changes the evidence is worse than
    no document, and the caller records the report as incomplete.
    """
    lossy = unrepresentable(markdown)
    if lossy:
        raise ValueError(
            "Report contains characters unsupported by the PDF font: "
            + ", ".join(f"U+{ord(char):04X}" for char in lossy)
        )
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos
    from fpdf.fonts import FontFace

    class _ReportPDF(FPDF):
        def footer(self) -> None:
            self.set_y(-12)
            self.set_font("Helvetica", size=8)
            self.set_text_color(110, 110, 110)
            self.cell(
                0,
                6,
                t("pdf_page_of", language=lang, page=self.page_no(), total=_PAGE_COUNT_ALIAS),
                align="R",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            self.set_text_color(0, 0, 0)

    pdf = _ReportPDF(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages(_PAGE_COUNT_ALIAS)
    pdf.set_margins(left=15, top=15, right=15)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_creation_date(_ensure_utc(created_at) if created_at else datetime.now(UTC))
    pdf.add_page()
    printable = pdf.w - pdf.l_margin - pdf.r_margin

    for block in parse_blocks(markdown):
        if block.kind in ("h1", "h2", "h3"):
            pdf.ln(3 if block.kind != "h1" else 1)
            pdf.set_font("Helvetica", style="B", size=_SIZE[block.kind])
            pdf.multi_cell(
                0,
                _LINE_HEIGHT[block.kind],
                block.text,
                align="L",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            pdf.ln(1)
        elif block.kind == "bullet":
            pdf.set_font("Helvetica", size=_SIZE["bullet"])
            pdf.set_x(pdf.l_margin)
            pdf.cell(5, _LINE_HEIGHT["bullet"], "-")
            pdf.multi_cell(
                0,
                _LINE_HEIGHT["bullet"],
                block.text,
                align="L",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
        elif block.kind == "table":
            pdf.set_font("Helvetica", size=_SIZE["table"])
            rows = [[_cap(cell) for cell in cells] for cells in block.rows]
            widths = _column_widths(rows, printable)
            with pdf.table(
                col_widths=tuple(widths),
                width=printable,
                text_align="LEFT",
                line_height=_LINE_HEIGHT["table"],
                headings_style=FontFace(emphasis="BOLD", fill_color=(235, 235, 235)),
                first_row_as_headings=True,
                padding=1,
            ) as table:
                for cells in rows:
                    row = table.row()
                    for index in range(len(widths)):
                        row.cell(cells[index] if index < len(cells) else "")
            pdf.ln(2)
        else:
            pdf.set_font("Helvetica", size=_SIZE["para"])
            pdf.multi_cell(
                0,
                _LINE_HEIGHT["para"],
                block.text,
                align="L",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            pdf.ln(1.5)

    pdf.output(str(path))
