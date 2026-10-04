#!/usr/bin/env python3
"""Render a business Markdown document to a formal PDF (cover page + body).

Usage:
    python scripts/render_business_pdf.py docs/business/<doc>.md [-o out.pdf]

Design notes:
- Uses fpdf2 (already a project dependency for run reports).
- Embeds the DejaVu font family when available on the host so the full
  Unicode range used by the docs (box-drawing diagrams, arrows, accents)
  renders correctly; falls back to the built-in Helvetica core fonts with a
  latin-1 sanitiser otherwise.
- Markdown support is intentionally pragmatic: ATX headings, paragraphs,
  bullet/numbered lists, blockquotes, fenced code blocks, pipe tables,
  horizontal rules and the inline subset fpdf2 understands (``**bold**``,
  ``*italic*``, ``` `code` ```, ``[text](url)``).

The script never raises on missing glyphs: unsupported characters are
replaced so a PDF is always produced.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import TableCellFillMode

# ── Font discovery ─────────────────────────────────────────────────────────────

_FONT_CANDIDATES = {
    "sans": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
    ],
    "sans_bold": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
    ],
    "mono": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    ],
}

# Characters with no latin-1 equivalent, replaced only in fallback mode.
_FALLBACK_REPLACEMENTS = {
    "✅": "[OK]",
    "✓": "x",
    "→": "->",
    "▼": "v",
    "⇒": "=>",
    "·": "-",
    "—": "--",
    "–": "-",
    "…": "...",
    "“": '"',
    "”": '"',
    "’": "'",
    "±": "+/-",
}
_BOX_CHARS = "│┌┐└┘├┤┬┴┼─═║╔╗╚╝"

_UNICODE_REPLACEMENTS = {"✅": "OK"}  # DejaVu has no U+2705 emoji glyph


def _find_font(paths: list[str]) -> Path | None:
    for candidate in paths:
        path = Path(candidate)
        if path.exists():
            return path
    return None


# ── Markdown block parsing ─────────────────────────────────────────────────────


@dataclass
class Block:
    kind: str  # heading | para | list | quote | code | table | hr
    level: int = 0
    lines: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)


_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_FENCE_RE = re.compile(r"^(```|~~~)")
_LIST_RE = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+")
_TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}")


def parse_markdown(text: str) -> list[Block]:
    """Split Markdown text into renderable blocks (line-based, pragmatic)."""
    blocks: list[Block] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped in {"---", "***", "___"}:
            blocks.append(Block(kind="hr"))
            i += 1
            continue

        heading = _HEADING_RE.match(line)
        if heading:
            blocks.append(
                Block(kind="heading", level=len(heading.group(1)), lines=[heading.group(2)])
            )
            i += 1
            continue

        if _FENCE_RE.match(stripped):
            i += 1
            code: list[str] = []
            while i < len(lines) and not _FENCE_RE.match(lines[i].strip()):
                code.append(lines[i])
                i += 1
            i += 1  # closing fence
            blocks.append(Block(kind="code", lines=code))
            continue

        if stripped.startswith("|"):
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                raw = lines[i].strip()
                if not _TABLE_SEP_RE.match(raw):
                    cells = [c.strip() for c in raw.strip("|").split("|")]
                    rows.append(cells)
                i += 1
            if rows:
                blocks.append(Block(kind="table", rows=rows))
            continue

        if stripped.startswith(">"):
            quote: list[str] = []
            while i < len(lines) and (lines[i].strip().startswith(">") or not lines[i].strip()):
                content = lines[i].strip()
                quote.append(content.lstrip(">").strip())
                i += 1
                if i < len(lines) and not lines[i].strip():
                    break
            blocks.append(Block(kind="quote", lines=[q for q in quote if q]))
            continue

        if _LIST_RE.match(line):
            items: list[str] = []
            while i < len(lines):
                item = _LIST_RE.match(lines[i])
                if item:
                    items.append(_LIST_RE.sub("", lines[i], count=1).strip())
                    i += 1
                    # Continuation lines (indented, not a new item).
                    while i < len(lines) and lines[i].startswith("   ") and lines[i].strip():
                        items[-1] += " " + lines[i].strip()
                        i += 1
                elif not lines[i].strip():
                    break
                else:
                    items[-1] += " " + lines[i].strip()
                    i += 1
            blocks.append(Block(kind="list", lines=items))
            continue

        para: list[str] = []
        while (
            i < len(lines)
            and lines[i].strip()
            and not _HEADING_RE.match(lines[i])
            and not _FENCE_RE.match(lines[i].strip())
            and not lines[i].strip().startswith("|")
            and not lines[i].strip().startswith(">")
            and not _LIST_RE.match(lines[i])
        ):
            para.append(lines[i].strip())
            i += 1
        blocks.append(Block(kind="para", lines=[" ".join(para)]))
    return blocks


# ── PDF rendering ──────────────────────────────────────────────────────────────


class DocumentPDF(FPDF):
    """FPDF subclass with a footer carrying page numbers and the project name."""

    def footer(self) -> None:  # noqa: D102 - fpdf2 hook
        if self.page_no() == 1:
            return
        self.set_y(-14)
        self.set_font(self._body_font, "", 7.5)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, f"OSINT Orchestrator — {self.page_no() - 1}", align="C")
        self.set_text_color(0, 0, 0)


def _sanitize(text: str, *, unicode_fonts: bool) -> str:
    """Replace characters the active font cannot render."""
    for emoji, replacement in _UNICODE_REPLACEMENTS.items():
        text = text.replace(emoji, replacement)
    # Flag emojis (regional indicators) are removed entirely, keeping the label.
    text = re.sub(r"[\U0001F1E6-\U0001F1FF]", "", text)
    text = text.replace("🇪🇸", "").replace("🇬🇧", "")
    if not unicode_fonts:
        for char, replacement in _FALLBACK_REPLACEMENTS.items():
            text = text.replace(char, replacement)
        for char in _BOX_CHARS:
            text = text.replace(char, "|" if char in "│║" else "-")
        text = text.encode("latin-1", "replace").decode("latin-1")
    return text


class BusinessDocRenderer:
    """Renders parsed Markdown blocks into a formal PDF document."""

    def __init__(self, title: str, subtitle: str = "") -> None:
        sans = _find_font(_FONT_CANDIDATES["sans"])
        sans_bold = _find_font(_FONT_CANDIDATES["sans_bold"])
        mono = _find_font(_FONT_CANDIDATES["mono"])
        self.unicode_fonts = bool(sans and sans_bold)

        self.pdf = DocumentPDF(format="A4")
        self.pdf.set_margins(left=20, top=18, right=20)
        self.pdf.set_auto_page_break(auto=True, margin=20)
        if self.unicode_fonts:
            self.pdf.add_font("Body", "", str(sans))
            self.pdf.add_font("Body", "B", str(sans_bold))
            self.pdf.add_font("Body", "I", str(sans))
            # markdown=True preloads every style combination, including BI.
            self.pdf.add_font("Body", "BI", str(sans_bold))
            self.pdf.add_font("Mono", "", str(mono or sans))
            self._body_font, self._mono_font = "Body", "Mono"
        else:
            self._body_font, self._mono_font = "helvetica", "courier"
        self.pdf._body_font = self._body_font  # used by footer()
        self.title = title
        self.subtitle = subtitle

    # -- helpers ---------------------------------------------------------------

    def _md(self, text: str) -> str:
        """Sanitise and translate Markdown emphasis to fpdf2's dialect.

        fpdf2 (markdown=True) understands ``**bold**``, ``__italic__`` and
        ``--underline--`` but not ``*italic*`` or code spans; convert the
        former and strip the backticks of the latter.
        """
        text = _sanitize(text, unicode_fonts=self.unicode_fonts)
        text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"__\1__", text)
        return text.replace("`", "")

    def _avail(self, offset: float = 0.0) -> float:
        """Usable width from the current x (plus *offset*) to the right margin."""
        pdf = self.pdf
        return pdf.w - pdf.r_margin - (pdf.get_x() + offset)

    def _text_block(
        self, text: str, *, size: float = 10.5, style: str = "", align: str = "J"
    ) -> None:
        self.pdf.set_x(self.pdf.l_margin)
        self.pdf.set_font(self._body_font, style, size)
        self.pdf.multi_cell(self._avail(), size * 0.55, self._md(text), align=align, markdown=True)

    # -- cover -----------------------------------------------------------------

    def render_cover(self, meta_lines: list[str], disclaimer: str) -> None:
        pdf = self.pdf
        pdf.add_page()
        pdf.set_y(48)
        pdf.set_font(self._body_font, "B", 13)
        pdf.set_text_color(90, 90, 90)
        pdf.cell(0, 8, self._md("OSINT Orchestrator"), align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(6)
        pdf.set_font(self._body_font, "B", 21)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(self._avail(), 11, self._md(self.title), align="C")
        if self.subtitle:
            pdf.ln(3)
            pdf.set_font(self._body_font, "", 12)
            pdf.set_text_color(90, 90, 90)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(self._avail(), 7, self._md(self.subtitle), align="C")
            pdf.set_text_color(0, 0, 0)
        pdf.ln(10)
        pdf.set_draw_color(150, 150, 150)
        pdf.line(60, pdf.get_y(), 150, pdf.get_y())
        pdf.ln(10)
        for line in meta_lines:
            pdf.set_font(self._body_font, "", 10.5)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(self._avail(), 6, self._md(line), align="C", markdown=True)
        pdf.set_y(-70)
        pdf.set_fill_color(244, 244, 244)
        pdf.set_font(self._body_font, "I", 8.5)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(
            self._avail(), 4.8, self._md(disclaimer), align="J", fill=True, markdown=True
        )

    # -- body ------------------------------------------------------------------

    def render_blocks(self, blocks: list[Block], *, skip_first_h1: bool = True) -> None:
        pdf = self.pdf
        pdf.add_page()
        seen_h1 = False
        for block in blocks:
            pdf.set_x(pdf.l_margin)
            if block.kind == "heading":
                text = block.lines[0]
                if block.level == 1:
                    if skip_first_h1 and not seen_h1:
                        seen_h1 = True
                        continue
                    pdf.ln(3)
                    pdf.set_font(self._body_font, "B", 16)
                    pdf.multi_cell(self._avail(), 8, self._md(text), markdown=False)
                elif block.level == 2:
                    pdf.ln(4)
                    pdf.set_font(self._body_font, "B", 13)
                    pdf.set_text_color(20, 60, 130)
                    pdf.multi_cell(self._avail(), 7, self._md(text), markdown=False)
                    pdf.set_text_color(0, 0, 0)
                    pdf.set_draw_color(200, 200, 200)
                    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
                    pdf.ln(2)
                else:
                    pdf.ln(2)
                    pdf.set_font(self._body_font, "B", 11.5)
                    pdf.multi_cell(self._avail(), 6.5, self._md(text), markdown=False)
                pdf.ln(1)
            elif block.kind == "para":
                self._text_block(block.lines[0])
                pdf.ln(1.5)
            elif block.kind == "list":
                pdf.set_font(self._body_font, "", 10.5)
                for item in block.lines:
                    pdf.set_x(pdf.l_margin + 5)
                    pdf.multi_cell(
                        self._avail(), 5.8, self._md(f"-  {item}"), align="J", markdown=True
                    )
                pdf.ln(1.5)
            elif block.kind == "quote":
                pdf.set_fill_color(245, 247, 250)
                pdf.set_font(self._body_font, "I", 9.5)
                for line in block.lines:
                    pdf.set_x(pdf.l_margin + 4)
                    pdf.multi_cell(
                        self._avail(), 5.2, self._md(line), align="J", fill=True, markdown=True
                    )
                pdf.ln(1.5)
            elif block.kind == "code":
                pdf.set_fill_color(244, 244, 244)
                pdf.set_font(self._mono_font, "", 7.6)
                for line in block.lines or [""]:
                    pdf.set_x(pdf.l_margin)
                    pdf.multi_cell(
                        self._avail(), 4.1, self._md(line.rstrip()), fill=True, markdown=False
                    )
                pdf.set_font(self._body_font, "", 10.5)
                pdf.ln(1.5)
            elif block.kind == "table":
                self._render_table(block.rows)
                pdf.ln(2)
            elif block.kind == "hr":
                pdf.ln(1)
                pdf.set_draw_color(210, 210, 210)
                pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
                pdf.ln(3)

    def _render_table(self, rows: list[list[str]]) -> None:
        pdf = self.pdf
        if not rows:
            return
        columns = max(len(row) for row in rows)
        widths = [1] * columns
        for idx, row in enumerate(rows):
            for col, cell in enumerate(row):
                weights = 2.2 if idx == 0 else 1.0
                widths[col] = max(widths[col], weights * max(1, len(_strip_md(cell)) // 22 + 1))
        pdf.set_font(self._body_font, "", 8.8)
        from fpdf.fonts import FontFace

        with pdf.table(
            col_widths=widths,
            text_align="LEFT",
            line_height=4.6,
            padding=1.4,
            cell_fill_color=(240, 244, 250),
            cell_fill_mode=TableCellFillMode.ROWS,
            headings_style=FontFace(emphasis="BOLD", size_pt=8.8),
        ) as table:
            for row in rows:
                table_row = table.row()
                for col in range(columns):
                    cell_text = row[col] if col < len(row) else ""
                    table_row.cell(
                        _sanitize(_strip_md(cell_text), unicode_fonts=self.unicode_fonts)
                    )
        pdf.set_font(self._body_font, "", 10.5)


_MD_INLINE_RE = re.compile(r"(\*\*|__|\*|`|\[|\]\([^)]*\))")


def _strip_md(text: str) -> str:
    """Remove inline Markdown emphasis/code/links for table cells."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    return text.replace("**", "").replace("__", "").replace("*", "").replace("`", "")


# ── Document assembly ──────────────────────────────────────────────────────────


_META_LINE_RE = re.compile(
    r"^\*\*(?:Última revisión|Last reviewed|Audiencia|Audience|Tipo de documento|Document type)\*\*"
)


def render(markdown_path: Path, output_path: Path) -> None:
    """Render one Markdown business document to a formal PDF."""
    text = markdown_path.read_text(encoding="utf-8")
    blocks = parse_markdown(text)

    title = next(
        (b.lines[0] for b in blocks if b.kind == "heading" and b.level == 1), markdown_path.stem
    )

    # Metadata lines and the disclaimer go on the cover page; they are
    # removed from the body so nothing is rendered twice.
    meta_lines = [line.strip() for line in text.splitlines() if _META_LINE_RE.match(line.strip())]
    disclaimer = ""
    kept: list[Block] = []
    for block in blocks:
        if block.kind == "quote":
            joined = " ".join(block.lines)
            if "[English](" in joined or "[Español](" in joined:
                continue  # language-switch link
            if not disclaimer and (
                "descargo" in joined.lower()
                or "disclaimer" in joined.lower()
                or "alcance" in joined.lower()
            ):
                disclaimer = joined
                continue
        if block.kind == "para" and block.lines and _META_LINE_RE.match(block.lines[0]):
            continue  # metadata paragraph, now on the cover
        kept.append(block)

    renderer = BusinessDocRenderer(title=title)
    renderer.render_cover(meta_lines, disclaimer)
    renderer.render_blocks(kept)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    renderer.pdf.output(str(output_path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("markdown", type=Path, help="Markdown document to render")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Output PDF path")
    args = parser.parse_args(argv)

    source: Path = args.markdown
    if not source.exists():
        print(f"ERROR: {source} not found", file=sys.stderr)
        return 1
    output: Path = args.output or source.with_suffix(".pdf")
    render(source, output)
    print(f"PDF written to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
