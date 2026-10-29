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

A declaration this script finds but cannot read is reported as a problem, not
ignored: a pin that changes shape (a branch instead of a commit, a quoted SHA,
a Dockerfile that goes missing) must turn the run red, because a green run over
fewer pins than it was written to watch is the failure mode that looks like
success.

Exit codes: 0 every pin is at its upstream head, 1 at least one moved,
2 the check is incomplete (a pin could not be read, or a declaration it was
meant to parse no longer parses).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

SHA = r"[0-9a-f]{40}"
# `openosint @ git+https://github.com/careb36/OpenOSINT@<sha>` in pyproject.toml.
PEP508_GIT = re.compile(rf"git\+https://github\.com/([\w.-]+/[\w.-]+)@({SHA})")
PEP508_GIT_ANY = re.compile(r"git\+https://github\.com/([\w.-]+/[\w.-]+)@([^\s\"']+)")
# `context: https://github.com/smicallef/spiderfoot.git#<sha>` in a compose file.
BUILD_CONTEXT = re.compile(rf"https://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?#({SHA})")
BUILD_CONTEXT_ANY = re.compile(r"https://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?#([^\s#]+)")
# `ARG SOCIALOSINT_REF=<sha>` in a Dockerfile, attributed to the GitHub URL in
# the comment above it. The value may be quoted.
DOCKERFILE_ARG = re.compile(rf"^ARG\s+(\w+)=[\"']?({SHA})[\"']?\s*$", re.MULTILINE)
DOCKERFILE_ARG_ANY = re.compile(r"^ARG\s+(\w+)=[\"']?([^\"'\s]+)[\"']?\s*$", re.MULTILINE)
REF_ARG_NAME = re.compile(r"_(?:REF|SHA|COMMIT|PIN)$")
GITHUB_URL = re.compile(r"https://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?(?:#|\s|$)")
COMPOSE_SERVICE = re.compile(r"^  ([\w.-]+):\s*$", re.MULTILINE)


# `resolve_upstream` returns this only when the lookup itself failed, so the
# caller can tell "this repository is not a fork" from "we do not know whether
# it is a fork". The second case must fail the run, not pass as "no fork".
class UpstreamLookupError(Exception):
    pass


@dataclass(frozen=True)
class Pin:
    """One commit pinned in one file."""

    repo: str
    ref: str
    source: str
    detail: str


@dataclass(frozen=True)
class Problem:
    """A declaration the script was meant to parse but could not."""

    source: str
    detail: str


@dataclass(frozen=True)
class Finding:
    pin: Pin
    head: str | None
    upstream_ahead: int | None
    kind: str  # "direct" | "fork" | "parent"
    incomplete: bool = False

    @property
    def moved(self) -> bool:
        if self.kind == "fork":
            # The fork is ours: its own head moving is not upstream drift, and
            # the pin is a specific commit, not the tip. The parent row is the
            # verdict.
            return False
        if self.kind == "parent":
            # The pin is a fork commit, so it is never equal to the parent's
            # head; equality means nothing here. What means "drift" is whether
            # upstream has commits the pin does not. A synchronized fork reports
            # 0 and must not be called moved.
            return self.upstream_ahead is not None and self.upstream_ahead > 0
        # A direct (non-fork) pin is an upstream commit, so the head matching it
        # is the only "current" state.
        return self.head is not None and self.head != self.pin.ref


def _pins_from_pyproject(root: Path) -> tuple[list[Pin], list[Problem]]:
    path = root / "pyproject.toml"
    if not path.exists():
        return [], []
    text = path.read_text(encoding="utf-8")
    pins = [
        Pin(repo=m.group(1), ref=m.group(2), source=path.name, detail="PEP 508 direct reference")
        for m in PEP508_GIT.finditer(text)
    ]
    problems = [
        Problem(path.name, f"{m.group(1)}@{m.group(2)} (not a full commit)")
        for m in PEP508_GIT_ANY.finditer(text)
        if not re.fullmatch(SHA, m.group(2))
    ]
    return pins, problems


def _pins_from_compose(root: Path) -> tuple[list[Pin], list[Problem]]:
    pins: list[Pin] = []
    problems: list[Problem] = []
    for path in sorted(root.glob("docker-compose*.yml")):
        text = path.read_text(encoding="utf-8")
        for match in BUILD_CONTEXT.finditer(text):
            services = COMPOSE_SERVICE.findall(text[: match.start()])
            pins.append(
                Pin(
                    repo=match.group(1),
                    ref=match.group(2),
                    source=path.name,
                    detail=services[-1] if services else "?",
                )
            )
        for match in BUILD_CONTEXT_ANY.finditer(text):
            if not re.fullmatch(SHA, match.group(2)):
                problems.append(Problem(path.name, f"{match.group(1)}#{match.group(2)[:12]}"))
    return pins, problems


def _pins_from_dockerfiles(root: Path) -> tuple[list[Pin], list[Problem]]:
    pins: list[Pin] = []
    problems: list[Problem] = []
    for path in sorted(root.glob("Dockerfile*")):
        text = path.read_text(encoding="utf-8")
        for match in DOCKERFILE_ARG.finditer(text):
            urls = GITHUB_URL.findall(text[: match.start()])
            if not urls:
                continue
            pins.append(
                Pin(repo=urls[-1], ref=match.group(2), source=path.name, detail=match.group(1))
            )
        for match in DOCKERFILE_ARG_ANY.finditer(text):
            name, value = match.group(1), match.group(2)
            if not re.fullmatch(SHA, value) and REF_ARG_NAME.search(name):
                problems.append(Problem(path.name, f"{name}={value} (not a full commit)"))
    return pins, problems


def collect_pins(root: Path) -> tuple[list[Pin], list[Problem]]:
    """Every commit this repository pins, read from the files that hold them."""
    pins: list[Pin] = []
    problems: list[Problem] = []
    for source in (_pins_from_pyproject, _pins_from_compose, _pins_from_dockerfiles):
        found_pins, found_problems = source(root)
        pins.extend(found_pins)
        problems.extend(found_problems)

    seen: set[tuple[str, str]] = set()
    unique: list[Pin] = []
    for pin in pins:
        if (pin.repo, pin.ref) not in seen:
            seen.add((pin.repo, pin.ref))
            unique.append(pin)
    return unique, problems


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
        if len(parts) == 2 and re.fullmatch(SHA, parts[0]):
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
    """
    try:
        output = run(["gh", "api", f"repos/{repo}/compare/{base}...{head}", "--jq", ".ahead_by"])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    stripped = output.strip()
    return int(stripped) if stripped.isdigit() else None


def resolve_upstream(repo: str, run: Callable[[list[str]], str] = _run) -> str | None:
    """Parent repository when *repo* is a fork, else None.

    Raises `UpstreamLookupError` when the lookup failed: a missing `gh`, a rate
    limit or a timeout must not be confused with "this is not a fork", because
    that would drop the parent row and let a fork drift unreported.
    """
    try:
        output = run(["gh", "api", f"repos/{repo}", "--jq", ".parent.full_name // empty"])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise UpstreamLookupError(repo) from exc
    return output.strip() or None


def survey(
    pins: Iterable[Pin],
    fetch: Callable[[str], str | None] = fetch_head,
    ahead: Callable[[str, str, str], int | None] = count_upstream_ahead,
    upstream: Callable[[str], str | None] = resolve_upstream,
) -> list[Finding]:
    findings: list[Finding] = []
    for pin in pins:
        head = fetch(pin.repo)
        try:
            parent = upstream(pin.repo)
        except UpstreamLookupError:
            findings.append(Finding(pin, head, None, "direct", incomplete=True))
            continue

        if parent is None:
            # A plain repository: its own head is the whole signal.
            delta = ahead(pin.repo, pin.ref, head) if head and head != pin.ref else None
            findings.append(Finding(pin, head, delta, "direct", incomplete=head is None))
            continue

        # A fork: show the fork's own tip for context, then judge the parent.
        findings.append(Finding(pin, head, None, "fork", incomplete=head is None))

        parent_head = fetch(parent)
        parent_ahead = (
            ahead(parent, pin.ref, parent_head) if parent_head and parent_head != pin.ref else None
        )
        findings.append(
            Finding(
                Pin(parent, pin.ref, pin.source, f"upstream of the {pin.repo} fork"),
                parent_head,
                parent_ahead,
                "parent",
                # A parent whose drift cannot be counted is unreadable: for a
                # fork, sha equality never holds, so the count is the verdict.
                incomplete=parent_head is None or parent_ahead is None,
            )
        )
    return findings


def render(findings: Iterable[Finding], problems: Iterable[Problem] = ()) -> str:
    findings = list(findings)
    problems = list(problems)
    lines = [
        "| Pin | Pinned | Upstream head | Commits upstream since the pin | Status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        head = finding.head[:7] if finding.head else "unreadable"
        if finding.incomplete:
            status = "incomplete"
        elif finding.kind == "fork":
            status = "fork tip"
        elif finding.moved:
            status = "MOVED"
        else:
            status = "current"
        if finding.incomplete or (finding.moved and finding.upstream_ahead is None):
            delta = "unknown"
        elif finding.upstream_ahead is None:
            delta = "—"
        else:
            delta = str(finding.upstream_ahead)
        lines.append(
            f"| `{finding.pin.repo}` ({finding.pin.source}, {finding.pin.detail}) "
            f"| `{finding.pin.ref[:7]}` | `{head}` | {delta} | {status} |"
        )
    for problem in problems:
        lines.append(f"| `{problem.source}` | — | — | — | unparseable: {problem.detail} |")

    moved = [f for f in findings if f.moved]
    incomplete = [f for f in findings if f.incomplete]
    lines.append("")
    if moved:
        lines.append(f"{len(moved)} of {len(findings)} pins moved upstream.")
    elif problems or incomplete:
        lines.append("No drift confirmed, but the check is incomplete.")
    else:
        lines.append(f"All {len(findings)} pins are at their upstream head.")
    if incomplete:
        lines.append(f"{len(incomplete)} pin(s) could not be read.")
    if problems:
        lines.append(f"{len(problems)} declaration(s) could not be parsed.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--no-ahead", action="store_true", help="skip the compare API call")
    args = parser.parse_args(argv)

    pins, problems = collect_pins(args.root)
    if not pins and not problems:
        print("No pinned commits found: the pin format changed.", file=sys.stderr)
        return 2
    ahead = (lambda *_: None) if args.no_ahead else count_upstream_ahead
    findings = survey(pins, ahead=ahead)
    print(render(findings, problems))
    if problems or any(f.incomplete for f in findings):
        return 2
    return 1 if any(f.moved for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
