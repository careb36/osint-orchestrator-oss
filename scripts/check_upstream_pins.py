#!/usr/bin/env python3
"""Report upstream movement on the dependency pins Dependabot cannot see.

Dependabot covers the image tags and the PyPI packages, but it has no support
for a dependency referenced by a git commit, for a compose `build.context`
pointing at a repository, or for an `ARG <NAME>=<sha>` inside a Dockerfile. Those
are exactly the three pins that carry code this project parses as untrusted
input, so without this script nothing would ever say that upstream moved.

The pins are read from the files themselves, not from a list kept here: a list
would silently disagree with `pyproject.toml` the first time someone bumped it.
The check is `git ls-remote`, so it needs no token, no clone and no API quota.

Exit codes: 0 every pin is at its upstream head, 1 at least one moved,
2 the pins could not be read (a pin changed shape, and this script needs fixing
before it can be trusted).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

# `openosint @ git+https://github.com/careb36/OpenOSINT@<sha>` in pyproject.toml.
PEP508_GIT = re.compile(r"git\+https://github\.com/([\w.-]+/[\w.-]+)@([0-9a-f]{40})")
# `context: https://github.com/smicallef/spiderfoot.git#<sha>` in a compose file.
BUILD_CONTEXT = re.compile(r"https://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?#([0-9a-f]{40})")
# `ARG SOCIALOSINT_REF=<sha>` in a Dockerfile, attributed to the GitHub URL in
# the comment above it.
DOCKERFILE_ARG = re.compile(r"^ARG\s+(\w+)=([0-9a-f]{40})\s*$", re.MULTILINE)
GITHUB_URL = re.compile(r"https://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?(?:#|\s|$)")
COMPOSE_SERVICE = re.compile(r"^  ([\w.-]+):\s*$", re.MULTILINE)


@dataclass(frozen=True)
class Pin:
    """One commit pinned in one file."""

    repo: str
    ref: str
    source: str
    detail: str

    @property
    def slug(self) -> str:
        return f"{self.repo}@{self.ref[:7]}"


@dataclass(frozen=True)
class Finding:
    pin: Pin
    head: str | None
    upstream_ahead: int | None

    @property
    def moved(self) -> bool:
        return self.head is not None and self.head != self.pin.ref


def _pins_from_pyproject(root: Path) -> list[Pin]:
    path = root / "pyproject.toml"
    if not path.exists():
        return []
    return [
        Pin(repo=m.group(1), ref=m.group(2), source=path.name, detail="PEP 508 direct reference")
        for m in PEP508_GIT.finditer(path.read_text(encoding="utf-8"))
    ]


def _pins_from_compose(root: Path) -> list[Pin]:
    found: list[Pin] = []
    for path in sorted(root.glob("docker-compose*.yml")):
        text = path.read_text(encoding="utf-8")
        for match in BUILD_CONTEXT.finditer(text):
            # Service keys sit at two-space indentation; `context:` itself sits
            # deeper, so matching the indentation is what picks `spiderfoot` and
            # not `context`.
            services = COMPOSE_SERVICE.findall(text[: match.start()])
            service = services[-1] if services else "?"
            found.append(
                Pin(repo=match.group(1), ref=match.group(2), source=path.name, detail=service)
            )
    return found


def _pins_from_dockerfiles(root: Path) -> list[Pin]:
    found: list[Pin] = []
    for path in sorted(root.glob("Dockerfile*")):
        text = path.read_text(encoding="utf-8")
        for match in DOCKERFILE_ARG.finditer(text):
            # The ARG rarely carries the URL, so take the last one above it.
            above = text[: match.start()]
            urls = GITHUB_URL.findall(above)
            if not urls:
                continue
            found.append(
                Pin(
                    repo=urls[-1],
                    ref=match.group(2),
                    source=path.name,
                    detail=match.group(1),
                )
            )
    return found


def collect_pins(root: Path) -> list[Pin]:
    """Every commit this repository pins, read from the files that hold them."""
    pins = _pins_from_pyproject(root) + _pins_from_compose(root) + _pins_from_dockerfiles(root)
    seen: set[tuple[str, str]] = set()
    unique: list[Pin] = []
    for pin in pins:
        if (pin.repo, pin.ref) not in seen:
            seen.add((pin.repo, pin.ref))
            unique.append(pin)
    return unique


def _run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=True)  # noqa: S603 - fixed argv, no shell
    return result.stdout


def fetch_head(repo: str, run: Callable[[list[str]], str] = _run) -> str | None:
    """SHA of *repo*'s default branch, or None when it cannot be read.

    `HEAD` is the remote's default branch whatever it is called, so this keeps
    working if a project renames `master` to `main`.
    """
    url = f"https://github.com/{repo}"
    try:
        output = run(["git", "ls-remote", "--exit-code", url, "HEAD"])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{40}", parts[0]):
            return parts[0]
    return None


def count_upstream_ahead(
    repo: str, base: str, head: str, run: Callable[[list[str]], str] = _run
) -> int | None:
    """Commits upstream has that the pin does not, when GitHub will say.

    `ahead_by`, not `behind_by`: the question is how stale the pin is, so the
    count wanted is "commits in head that base lacks". `behind_by` here would
    report how many fork-only commits the pin carries, which reads almost the
    same in a table and answers a different question.

    Best effort: a rate limit, a network failure or a missing `gh` degrades to
    "unknown" rather than failing the whole run, because the drift itself is the
    signal and the count is the explanation.
    """
    try:
        output = run(["gh", "api", f"repos/{repo}/compare/{base}...{head}", "--jq", ".ahead_by"])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    stripped = output.strip()
    return int(stripped) if stripped.isdigit() else None


def resolve_upstream(repo: str, run: Callable[[list[str]], str] = _run) -> str | None:
    """Parent repository when *repo* is a fork, else None.

    This is the whole point of the script for `openosint`: the pin points at a
    fork, so comparing against the fork's own head reports "current" for as long
    as nobody pushes to the fork, while the code it was forked from moves on.
    Without the parent, the pin that most needs watching is the one that looks
    settled.
    """
    try:
        output = run(["gh", "api", f"repos/{repo}", "--jq", ".parent.full_name // empty"])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return output.strip() or None


def survey(
    pins: Iterable[Pin],
    fetch: Callable[[str], str | None] = fetch_head,
    ahead: Callable[[str, str, str], int | None] = count_upstream_ahead,
    upstream: Callable[[str], str | None] = resolve_upstream,
) -> list[Finding]:
    findings = []
    for pin in pins:
        head = fetch(pin.repo)
        delta = ahead(pin.repo, pin.ref, head) if head and head != pin.ref else None
        findings.append(Finding(pin=pin, head=head, upstream_ahead=delta))

        parent = upstream(pin.repo)
        if not parent:
            continue
        parent_head = fetch(parent)
        parent_delta = (
            ahead(parent, pin.ref, parent_head) if parent_head and parent_head != pin.ref else None
        )
        findings.append(
            Finding(
                pin=Pin(
                    repo=parent,
                    ref=pin.ref,
                    source=pin.source,
                    detail=f"upstream of the {pin.repo} fork",
                ),
                head=parent_head,
                upstream_ahead=parent_delta,
            )
        )
    return findings


def render(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    moved = [f for f in findings if f.moved]
    lines = [
        "| Pin | Pinned | Upstream head | Commits upstream since the pin | Status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        head = finding.head[:7] if finding.head else "unreadable"
        if not finding.moved:
            delta = "—"
        else:
            delta = "unknown" if finding.upstream_ahead is None else str(finding.upstream_ahead)
        status = "MOVED" if finding.moved else ("unreadable" if not finding.head else "current")
        lines.append(
            f"| `{finding.pin.repo}` ({finding.pin.source}, {finding.pin.detail}) "
            f"| `{finding.pin.ref[:7]}` | `{head}` | {delta} | {status} |"
        )
    unreadable = [f for f in findings if not f.head]
    lines.append("")
    if moved:
        lines.append(f"{len(moved)} of {len(findings)} pinned commits moved upstream.")
    else:
        lines.append(f"All {len(findings)} pinned commits are at their upstream head.")
    if unreadable:
        lines.append(
            f"{len(unreadable)} repository(ies) could not be read; the check is incomplete."
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument(
        "--no-behind",
        action="store_true",
        help="skip the compare API call (the counts, not the drift)",
    )
    args = parser.parse_args(argv)

    pins = collect_pins(args.root)
    if not pins:
        print("No pinned commits found: the pin format changed.", file=sys.stderr)
        return 2
    ahead = (lambda *_: None) if args.no_behind else count_upstream_ahead
    findings = survey(pins, ahead=ahead)
    print(render(findings))
    if any(not f.head for f in findings):
        return 2
    return 1 if any(f.moved for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
