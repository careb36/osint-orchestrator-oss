"""
Guard test: every GitHub Action is pinned to a commit SHA.

A moving tag (`actions/checkout@v4`) is re-pointed by its publisher, so the
code CI runs can change without a commit here. A full SHA cannot move, and a
Dependabot `github-actions` entry (`.github/dependabot.yml`) is what proposes
the new SHA as a reviewable diff. The `# v4` comment is kept so a human can
still read which release a pin corresponds to.

Reads the workflow files; needs no network.
"""

from __future__ import annotations

import pathlib
import re

import yaml

REPO_ROOT = pathlib.Path(__file__).parents[2]
WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))

# `owner/repo@ref`, optionally followed by a comment.
USES = re.compile(r"\buses:\s*(?P<action>[^\s#]+)")
SHA = re.compile(r"^[0-9a-f]{40}$")

# `uses: ./local/action` and `docker://image:tag` are not GitHub Actions from a
# repository and cannot be pinned by SHA.
NOT_A_REMOTE_ACTION = ("./", "docker://")


def _uses() -> list[tuple[str, str, str]]:
    found = []
    for workflow in WORKFLOWS:
        document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        for job in (document or {}).get("jobs", {}).values():
            for step in job.get("steps") or []:
                action = step.get("uses")
                if action:
                    found.append((workflow.name, action, step.get("name", "")))
    return found


def test_workflow_files_exist() -> None:
    assert WORKFLOWS, "no workflows found; the guard would pass vacuously"


def test_every_action_is_pinned_to_a_commit_sha() -> None:
    unpinned = []
    for workflow, action, step_name in _uses():
        if action.startswith(NOT_A_REMOTE_ACTION):
            continue
        _, _, ref = action.partition("@")
        if not SHA.match(ref):
            unpinned.append(f"{workflow}: {action} (step: {step_name})")
    assert not unpinned, (
        "pin these to a full 40-character commit SHA, keeping the tag as a "
        "# comment so the release stays readable:\n  " + "\n  ".join(unpinned)
    )


def test_pins_keep_a_readable_tag_comment() -> None:
    """A bare SHA is unreviewable: a reader cannot tell what was pinned."""
    missing = []
    for workflow in WORKFLOWS:
        for line in workflow.read_text(encoding="utf-8").splitlines():
            match = USES.search(line)
            if not match or match.group("action").startswith(NOT_A_REMOTE_ACTION):
                continue
            _, _, ref = match.group("action").partition("@")
            if SHA.match(ref) and "#" not in line:
                missing.append(f"{workflow.name}: {match.group('action')}")
    assert not missing, "add the tag as a comment (e.g. `# v4`):\n  " + "\n  ".join(missing)
