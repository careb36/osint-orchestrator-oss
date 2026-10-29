"""The notes of a release: the `## [<version>]` section of CHANGELOG.md.

`.github/workflows/release.yml` calls this with the tag minus its leading `v`.
It is a script rather than an inline heredoc so the extraction can be tested:
the section ends at the next level-2 heading, and CHANGELOG.md writes historical
sections as `## 2026-09-14` without brackets, so anchoring on `## [` alone made
every release swallow the whole history below it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"


def section(text: str, version: str) -> str | None:
    match = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    return match.group(1).strip() if match else None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: release_notes.py <version>", file=sys.stderr)
        return 2
    notes = section(CHANGELOG.read_text(encoding="utf-8"), argv[1])
    if not notes:
        print(
            f"CHANGELOG.md has no '## [{argv[1]}]' section with content; add it before tagging",
            file=sys.stderr,
        )
        return 1
    print(notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
