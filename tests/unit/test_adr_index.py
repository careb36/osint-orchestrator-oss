"""Every architecture decision is indexed, in both places that list them.

`AGENTS.md` says architecture decisions live in `docs/adr/` and that a change
must not contradict one "without proposing a new ADR". Two tables list those
decisions — the index in `docs/README.md` and the `## Decisions` table in
`docs/architecture.md` — and nothing kept either in step with the directory. The
index-completeness guard in `test_doc_links.py` globs `docs/*.md`, which does not
descend, so an ADR-014 could be accepted and linked from nowhere.

The failure this prevents is quiet: an unindexed ADR still renders, still has a
number, and is still cited by whoever wrote it. It is only invisible to the
person who joins later and reads the Decision table as the complete record.

Two tables are checked rather than one because they serve different readers —
the index is the entry point, the architecture page is where someone looks for
the decision record — and a new ADR has to reach both. Their one-line summaries
are deliberately *not* compared: the index abbreviates and the architecture page
expands, so requiring identical prose would force both to repeat each other.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
ADR_ROOT = DOCS / "adr"
TABLES = (DOCS / "README.md", DOCS / "architecture.md")
_ROW = re.compile(r"\[(\d{3})\]\((adr/[A-Za-z0-9._-]+\.md)\)")
_H1 = re.compile(r"^# ADR-(\d{3}):\s*\S")
_STATUS = re.compile(r"(?m)^\*\*Status:\*\*\s*\S")


def _adr_files() -> list[Path]:
    files = sorted(ADR_ROOT.glob("*.md"))
    assert files, "no ADRs found under docs/adr"
    return files


def _rows(table: Path) -> list[tuple[str, str]]:
    rows = _ROW.findall(table.read_text(encoding="utf-8"))
    assert rows, f"no ADR rows parsed from {table.relative_to(ROOT)} — did the table change shape?"
    return rows


@pytest.mark.parametrize("table", TABLES, ids=lambda path: path.name)
def test_every_adr_is_listed(table: Path) -> None:
    listed = {path for _, path in _rows(table)}
    unlisted = sorted(f"adr/{adr.name}" for adr in _adr_files() if f"adr/{adr.name}" not in listed)
    assert unlisted == [], (
        f"ADRs that {table.relative_to(ROOT)} never lists: {unlisted}. Add a row to "
        "its table, or the decision is only discoverable by browsing the directory."
    )


@pytest.mark.parametrize("table", TABLES, ids=lambda path: path.name)
def test_every_listed_adr_exists(table: Path) -> None:
    dangling = sorted(
        f"[{number}] {path}" for number, path in _rows(table) if not (DOCS / path).is_file()
    )
    assert dangling == [], (
        f"rows in {table.relative_to(ROOT)} that point at no file: {dangling}. A "
        "reader following the link of a superseded ADR hits a 404."
    )


@pytest.mark.parametrize("table", TABLES, ids=lambda path: path.name)
def test_the_row_number_matches_the_filename(table: Path) -> None:
    """`[014](adr/ADR-013-...)` is a copy-paste that renumbers a decision."""
    wrong = sorted(
        f"[{number}] -> {path}"
        for number, path in _rows(table)
        if not path.startswith(f"adr/ADR-{number}-")
    )
    assert wrong == [], (
        f"rows in {table.relative_to(ROOT)} whose number disagrees with the file: "
        f"{wrong}. The number is the citation, so it has to point at the decision."
    )


@pytest.mark.parametrize("table", TABLES, ids=lambda path: path.name)
def test_no_adr_is_listed_twice(table: Path) -> None:
    numbers = [number for number, _ in _rows(table)]
    duplicated = sorted({number for number in numbers if numbers.count(number) > 1})
    assert duplicated == [], (
        f"ADR numbers listed more than once in {table.relative_to(ROOT)}: {duplicated}. "
        "One row per decision; a second row is an edit that landed on a stale copy."
    )


def test_both_tables_list_the_same_decisions() -> None:
    listed = {table.name: {path for _, path in _rows(table)} for table in TABLES}
    first, second = (listed[table.name] for table in TABLES)
    assert first == second, (
        "the two ADR tables disagree: "
        f"only in {TABLES[0].name}: {sorted(first - second)}; "
        f"only in {TABLES[1].name}: {sorted(second - first)}."
    )


def test_each_adr_title_carries_its_own_number() -> None:
    """A template copied for ADR-014 that still says `# ADR-013` splits one decision."""
    wrong = {}
    for adr in _adr_files():
        match = _H1.search(adr.read_text(encoding="utf-8"))
        expected = re.match(r"ADR-(\d{3})-", adr.name)
        if not match or not expected:
            wrong[adr.name] = "no '# ADR-nnn: Title' heading"
        elif match.group(1) != expected.group(1):
            wrong[adr.name] = f"heading says ADR-{match.group(1)}"
    assert wrong == {}, f"ADR files whose heading disagrees with their filename: {wrong}"


def test_adr_numbers_are_unique() -> None:
    numbers = [re.match(r"ADR-(\d{3})-", adr.name).group(1) for adr in _adr_files()]
    duplicated = sorted({number for number in numbers if numbers.count(number) > 1})
    assert duplicated == [], f"ADR numbers reused by more than one file: {duplicated}"


def test_each_adr_states_its_status() -> None:
    """A decision whose status no one recorded cannot be told from a proposal."""
    missing = [
        adr.name for adr in _adr_files() if not _STATUS.search(adr.read_text(encoding="utf-8"))
    ]
    assert missing == [], f"ADR files with no '**Status:**' line: {missing}"
