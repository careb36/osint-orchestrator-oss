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
DOCS = REPO_ROOT / "docs"
INDEX = DOCS / "README.md"
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


def test_the_index_links_every_page_under_docs() -> None:
    """A new page that the index never mentions is a page nobody finds."""
    index = INDEX.read_text(encoding="utf-8")
    pages = {path.name for path in DOCS.glob("*.md")} - {INDEX.name}
    unlisted = sorted(page for page in pages if f"({page})" not in index)
    assert unlisted == [], (
        f"pages under docs/ that docs/README.md never links: {unlisted}. "
        "Add them to the index in the section a reader would look in."
    )


# `[label](target)`, but not `![alt](image)`. A target without a `#` is the
# other test's business; this one is only about the fragment.
_ANCHOR_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$", re.M)
_FENCE = re.compile(r"```.*?```", re.S)
_CAMEL = re.compile(r"-{2,}")


def _slug(heading: str) -> str:
    """GitHub's heading fragment: lowercase, code and links keep their text."""
    text = heading.strip().lower()
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\s-]", "", text).strip()
    return re.sub(r"\s+", "-", text)


def _headings(path: Path) -> set[str]:
    """Every fragment a heading in *path* can be reached by.

    Fenced code is dropped so a `# comment` inside a shell block is not read as
    a heading. Duplicate headings get the `-1`, `-2` suffixes GitHub appends.
    """
    text = _FENCE.sub("", path.read_text(encoding="utf-8"))
    fragments: set[str] = set()
    seen: dict[str, int] = {}
    for match in _HEADING.finditer(text):
        slug = _slug(match.group(2))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        fragments.add(slug if not count else f"{slug}-{count}")
    return fragments


def _matches(anchor: str, fragments: set[str]) -> bool:
    # Runs of hyphens are collapsed on both sides: a heading whose punctuation
    # is stripped can yield `a--b` from one slugger and `a-b` from another, and
    # that difference is not a broken link.
    wanted = _CAMEL.sub("-", anchor)
    return any(_CAMEL.sub("-", fragment) == wanted for fragment in fragments)


def test_internal_anchor_links_reach_a_heading() -> None:
    """`operations.md#evidence-chain` must land on a heading, not on the top.

    The sibling test only checks that the *file* exists, so a link to a renamed
    heading still passed: the browser silently ignores the unknown fragment and
    renders the page from the start. `docs/configuration.md` pointed at
    `#evidence-chain` while the heading is "Reports and evidence chain", so an
    operator rotating `ORCHESTRATOR_SECRET_KEY_PREVIOUS` arrived at the top of a
    long page with no indication of where the procedure was.
    """
    checked = 0
    broken: dict[str, list[str]] = {}
    for path in _tracked_text_files():
        if path.suffix != ".md" or path.name == "CHANGELOG.md":
            continue
        text = _FENCE.sub("", path.read_text(encoding="utf-8"))
        for target in _ANCHOR_LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            destination, _, anchor = target.partition("#")
            if not anchor:
                continue
            resolved = (path.parent / destination).resolve() if destination else path
            if not resolved.exists():
                continue  # the other test reports a missing file
            checked += 1
            if not _matches(anchor, _headings(resolved)):
                broken.setdefault(f"{path.relative_to(REPO_ROOT)} -> {target}", []).append(
                    str(resolved.relative_to(REPO_ROOT))
                )
    assert checked >= 8, f"only {checked} anchored links found; the scan is not reading them"
    assert broken == {}, (
        f"anchored links that reach no heading: {broken}. Fix the fragment or the "
        "heading, whichever is the typo."
    )
