"""The release notes of a tag are that version's CHANGELOG section and nothing else.

The extractor anchored its end on `## [` while CHANGELOG.md writes historical
sections as `## 2026-09-14`, so the first release cut after this changelog
existed would have published the entire history as its notes.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "release_notes", REPO_ROOT / "scripts" / "release_notes.py"
)
assert _SPEC and _SPEC.loader
release_notes = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(release_notes)

_HISTORY = """# Changelog

## [Unreleased]

### Added

- The unreleased entry.

## [1.3.0] - 2026-10-01

### Fixed

- The released entry.

## 2026-09-14

### Added

- An older entry, dated without brackets.

[Unreleased]: https://example.invalid/compare
"""


def test_a_section_stops_at_an_unbracketed_history_heading():
    notes = release_notes.section(_HISTORY, "1.3.0")

    assert notes == "### Fixed\n\n- The released entry."
    assert "dated without brackets" not in notes
    assert "[Unreleased]" not in notes


def test_the_unreleased_section_is_reachable_by_its_own_name():
    notes = release_notes.section(_HISTORY, "Unreleased")

    assert notes == "### Added\n\n- The unreleased entry."


def test_the_real_changelog_does_not_leak_its_history():
    # The shape that broke: promote [Unreleased] to a version and read it back.
    text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    promoted = text.replace("## [Unreleased]", "## [9.9.9] - 2026-10-29", 1)

    notes = release_notes.section(promoted, "9.9.9")

    assert notes
    assert not any(line.startswith("## ") for line in notes.splitlines())
    assert "commits/main" not in notes  # the link-reference footer stays out


def test_a_missing_version_fails_the_build(capsys):
    assert release_notes.main(["release_notes.py", "0.0.0-unreleased"]) == 1
    assert "has no '## [0.0.0-unreleased]'" in capsys.readouterr().err


def test_a_section_without_content_fails_the_build(tmp_path, capsys, monkeypatch):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("## [2.0.0] - 2026-10-01\n\n## [1.0.0] - 2026-09-01\n", encoding="utf-8")
    monkeypatch.setattr(release_notes, "CHANGELOG", changelog)

    assert release_notes.main(["release_notes.py", "2.0.0"]) == 1
    assert "with content" in capsys.readouterr().err


def test_the_workflow_runs_this_script():
    workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "scripts/release_notes.py" in workflow
    # No second copy of the extraction living inline in the workflow.
    assert "re.escape(version)" not in workflow
