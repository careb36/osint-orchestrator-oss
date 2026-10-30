"""ADR-009 keeps `README.es.md` in step with `README.md`.

The ADR makes the Spanish README the only translation and requires it to change
"in the same PR as `README.md`, with the same sections". Nothing enforced that,
so a section, a quickstart block, a documentation link or a screenshot added to
one page and not the other left the two READMEs describing different products —
the drift a reader of the other language cannot see, because nothing in their
copy looks missing.

Section titles are translated, so parity is checked by count and by the
artefacts both pages point at, not by matching text. The two demo GIFs are
shared; the dashboard screenshots are shot per language and pair up once the
locale suffix is stripped.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGES = {"en": ROOT / "README.md", "es": ROOT / "README.es.md"}

_DOC_PAGE = re.compile(r"docs/[A-Za-z0-9._/-]+\.md")
_IMAGE = re.compile(r"docs/img/[A-Za-z0-9._-]+")
_LOCALE = re.compile(r"-(?:en|es)$")


@pytest.fixture(scope="module")
def pages() -> dict[str, str]:
    return {language: path.read_text(encoding="utf-8") for language, path in PAGES.items()}


def _sections(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("## ")]


def test_both_readmes_have_the_same_sections(pages: dict[str, str]) -> None:
    english, spanish = _sections(pages["en"]), _sections(pages["es"])
    assert len(english) == len(spanish), (
        f"README.md has {len(english)} sections, README.es.md has {len(spanish)}:\n"
        f"en: {english}\nes: {spanish}"
    )


def test_both_readmes_carry_the_same_command_blocks(pages: dict[str, str]) -> None:
    counted = {language: text.count("```") for language, text in pages.items()}
    assert counted["en"] == counted["es"], (
        f"fenced block delimiters: {counted}. A quickstart step or a code sample "
        "was added or removed in one language only."
    )


def test_both_readmes_link_to_the_same_documentation(pages: dict[str, str]) -> None:
    linked = {language: set(_DOC_PAGE.findall(text)) for language, text in pages.items()}
    assert linked["en"] == linked["es"], (
        "the two READMEs point at different documentation pages. "
        f"Only in README.md: {sorted(linked['en'] - linked['es'])}. "
        f"Only in README.es.md: {sorted(linked['es'] - linked['en'])}."
    )


def test_both_readmes_show_the_same_screenshots(pages: dict[str, str]) -> None:
    def stems(text: str) -> set[str]:
        return {
            _LOCALE.sub("", Path(image).stem) + Path(image).suffix for image in _IMAGE.findall(text)
        }

    english, spanish = stems(pages["en"]), stems(pages["es"])
    assert english == spanish, (
        "the two READMEs show different images. "
        f"Only in README.md: {sorted(english - spanish)}. "
        f"Only in README.es.md: {sorted(spanish - english)}."
    )
