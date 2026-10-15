"""Every documentation page path (under `docs/`, ending in `.md`) that a tracked
text file mentions exists.

The SocialOSINT page was removed in the documentation restructure and five
files kept pointing at it; this keeps the next removal honest.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
_TEXT_SUFFIXES = {".md", ".py", ".toml", ".yml", ".yaml", ".txt", ".example", ""}
# A page path, optionally written relative to the citing file with a leading
# dot segment or two. The lookbehind keeps a page under the dashboard's own
# documentation directory from matching as a page under the root one.
_DOC_PATH = re.compile(r"(?<![\w/.-])(?:\.\./|\./)*docs/(?:adr/)?[A-Za-z0-9._-]+\.md")


def _tracked_text_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, check=True, capture_output=True, text=True
    ).stdout
    return [
        REPO_ROOT / line
        for line in out.splitlines()
        if Path(line).suffix in _TEXT_SUFFIXES or Path(line).name.startswith("Dockerfile")
    ]


def test_every_referenced_docs_file_exists() -> None:
    missing: dict[str, list[str]] = {}
    for path in _tracked_text_files():
        if path.name == "CHANGELOG.md":  # history may legitimately name removed files
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for match in set(_DOC_PATH.findall(text)):
            # A Markdown link is relative to its file; prose and code name
            # the path from the repository root. A path that starts with a dot
            # segment is only ever relative to its file.
            candidates = [path.parent / match]
            if not match.startswith("."):
                candidates.append(REPO_ROOT / match)
            if not any(candidate.exists() for candidate in candidates):
                missing.setdefault(match, []).append(str(path.relative_to(REPO_ROOT)))
    assert missing == {}, f"references to documentation files that do not exist: {missing}"
