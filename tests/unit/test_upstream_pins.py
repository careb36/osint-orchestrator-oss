"""Tests for scripts/check_upstream_pins.py.

Offline by construction: every function that reaches the network takes its
runner as an argument, so these tests pass a stub and never open a socket.

The pins are read from the real `pyproject.toml`, `docker-compose.yml` and
`Dockerfile*` of this repository, because the failure mode worth guarding is
that someone bumps a pin into a shape the parser does not recognise and the
checker quietly reports nothing.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_upstream_pins.py"
ROOT = SCRIPT.parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("check_upstream_pins", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # Registered before exec_module: the dataclasses here use
    # `from __future__ import annotations`, and dataclasses resolves the string
    # annotations through sys.modules[cls.__module__].
    sys.modules["check_upstream_pins"] = module
    spec.loader.exec_module(module)
    return module


pins = _load()

PINNED = "f8855bfbd9c78a6d8c24639b1c30900a963e8f57"
MOVED_TO = "4acf13d0000000000000000000000000000000000"


def _ls_remote(sha: str):
    def run(command):
        assert command[:2] == ["git", "ls-remote"]
        return f"{sha}\tHEAD\n"

    return run


def _pin(repo=PINNED and "o/r", ref=PINNED, source="pyproject.toml", detail="x"):
    return pins.Pin(repo, ref, source, detail)


# ── parsing the pins out of the real files ──────────────────────────────────


def test_collect_pins_finds_the_three_pins_dependabot_cannot_see():
    found, problems = pins.collect_pins(ROOT)
    assert {pin.repo for pin in found} == {
        "careb36/OpenOSINT",
        "smicallef/spiderfoot",
        "bm-github/owasp-social-osint-agent",
    }
    assert problems == []


def test_collect_pins_returns_full_sixes():
    found, _ = pins.collect_pins(ROOT)
    for pin in found:
        assert len(pin.ref) == 40
        assert pin.ref == pin.ref.lower()


def test_compose_pin_is_attributed_to_its_service_not_to_the_context_key():
    found, _ = pins.collect_pins(ROOT)
    spiderfoot = next(pin for pin in found if pin.repo == "smicallef/spiderfoot")
    assert spiderfoot.detail == "spiderfoot"
    assert spiderfoot.source == "docker-compose.yml"


def test_dockerfile_pin_takes_the_url_above_the_arg(tmp_path):
    (tmp_path / "Dockerfile.thing").write_text(
        "# Source: https://github.com/some-org/some-repo (MIT)\n"
        "FROM python:3.11-slim\n"
        f"ARG THING_REF={PINNED}\n",
        encoding="utf-8",
    )
    found, problems = pins.collect_pins(tmp_path)
    assert [(pin.repo, pin.ref, pin.detail) for pin in found] == [
        ("some-org/some-repo", PINNED, "THING_REF")
    ]
    assert problems == []


def test_dockerfile_pin_accepts_a_quoted_sha(tmp_path):
    # Regression: the first version required an unquoted 40-hex, so
    # `ARG SOCIALOSINT_REF="<sha>"` was silently dropped while the other two
    # pins stayed green.
    (tmp_path / "Dockerfile.thing").write_text(
        "# Source: https://github.com/some-org/some-repo (MIT)\n"
        "FROM python:3.11-slim\n"
        f'ARG THING_REF="{PINNED}"\n',
        encoding="utf-8",
    )
    found, problems = pins.collect_pins(tmp_path)
    assert [pin.ref for pin in found] == [PINNED]
    assert problems == []


def test_collect_pins_deduplicates_the_same_commit_pinned_twice(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  one:\n"
        f"    build:\n      context: https://github.com/o/r.git#{PINNED}\n"
        "  two:\n"
        f"    build:\n      context: https://github.com/o/r.git#{PINNED}\n",
        encoding="utf-8",
    )
    found, _ = pins.collect_pins(tmp_path)
    assert len(found) == 1


def test_collect_pins_reports_a_ref_arg_that_stopped_being_a_commit(tmp_path):
    # Regression: a pin relaxed from a commit to a branch/tag must fail the
    # run, not vanish and leave the other pins "green".
    (tmp_path / "Dockerfile.thing").write_text(
        "# Source: https://github.com/some-org/some-repo (MIT)\n"
        "FROM python:3.11-slim\n"
        "ARG THING_REF=main\n",
        encoding="utf-8",
    )
    found, problems = pins.collect_pins(tmp_path)
    assert found == []
    assert [problem.detail for problem in problems] == ["THING_REF=main (not a full commit)"]


def test_collect_pins_ignores_a_non_ref_arg(tmp_path):
    # `PIP_SECURITY_UPGRADES` is a real ARG that is not a pin; it must not be
    # mistaken for a broken one.
    (tmp_path / "Dockerfile.thing").write_text(
        'FROM python:3.11-slim\nARG PIP_SECURITY_UPGRADES="setuptools==1 pillow==2"\n',
        encoding="utf-8",
    )
    _, problems = pins.collect_pins(tmp_path)
    assert problems == []


# ── reading the remote ──────────────────────────────────────────────────────


def test_fetch_head_returns_the_default_branch_sha():
    assert pins.fetch_head("o/r", run=_ls_remote(PINNED)) == PINNED


def test_fetch_head_returns_none_when_the_remote_cannot_be_read():
    def run(command):
        raise subprocess.CalledProcessError(128, command)

    assert pins.fetch_head("o/r", run=run) is None


def test_upstream_ahead_asks_github_for_ahead_by():
    # Regression guard: the field was behind_by while the docstring and the
    # column said "how far behind is the pin", so the table reported the
    # fork-only commits (22) instead of the upstream ones (161).
    seen = {}

    def run(command):
        seen["command"] = command
        return "161\n"

    assert pins.count_upstream_ahead("o/r", PINNED, MOVED_TO, run=run) == 161
    assert seen["command"][-1] == ".ahead_by"


# ── fork handling ───────────────────────────────────────────────────────────


def test_resolve_upstream_distinguishes_a_fork_from_a_plain_repo():
    def run(command):
        assert "repos/o/r" in command[2]
        return "upstream/r\n"

    assert pins.resolve_upstream("o/r", run=run) == "upstream/r"

    def no_parent(command):
        return "\n"

    assert pins.resolve_upstream("o/r", run=no_parent) is None


def test_resolve_upstream_raises_when_the_lookup_fails_instead_of_passing():
    def run(command):
        raise subprocess.CalledProcessError(1, command)

    with pytest.raises(pins.UpstreamLookupError):
        pins.resolve_upstream("o/r", run=run)


def test_survey_reports_the_fork_parent_and_does_not_call_the_fork_moved():
    def fetch(repo):
        return PINNED if repo == "careb36/OpenOSINT" else MOVED_TO

    findings = pins.survey(
        [pins.Pin("careb36/OpenOSINT", PINNED, "pyproject.toml", "x")],
        fetch=fetch,
        ahead=lambda *_: 161,
        upstream=lambda repo: "OpenOSINT/OpenOSINT",
    )
    fork, parent = findings
    assert fork.kind == "fork" and not fork.moved
    assert parent.kind == "parent" and parent.moved
    assert parent.upstream_ahead == 161


def test_survey_does_not_mark_a_synchronized_fork_as_moved():
    # Regression: when the fork has merged every upstream commit, the parent's
    # ahead count is 0 and the run must not fail.
    findings = pins.survey(
        [pins.Pin("careb36/OpenOSINT", PINNED, "pyproject.toml", "x")],
        fetch=lambda repo: MOVED_TO,
        ahead=lambda *_: 0,
        upstream=lambda repo: "OpenOSINT/OpenOSINT",
    )
    assert [f for f in findings if f.kind == "parent"][0].moved is False
    assert not any(f.moved for f in findings)


def test_survey_marks_the_check_incomplete_when_the_parent_lookup_fails():
    # Regression: a failed `gh` lookup returned the same None as "not a fork"
    # and dropped the parent row, so a fork could drift unreported.
    def fail(repo):
        raise pins.UpstreamLookupError(repo)

    findings = pins.survey(
        [pins.Pin("careb36/OpenOSINT", PINNED, "pyproject.toml", "x")],
        fetch=lambda repo: PINNED,
        ahead=lambda *_: 0,
        upstream=fail,
    )
    assert len(findings) == 1
    assert findings[0].incomplete


def test_survey_marks_the_parent_incomplete_when_its_count_cannot_be_read():
    # For a fork the sha is never equal to the parent head, so the count is the
    # only verdict. A missing count is "unreadable", not "current".
    findings = pins.survey(
        [pins.Pin("careb36/OpenOSINT", PINNED, "pyproject.toml", "x")],
        fetch=lambda repo: MOVED_TO,
        ahead=lambda *_: None,
        upstream=lambda repo: "OpenOSINT/OpenOSINT",
    )
    parent = [f for f in findings if f.kind == "parent"][0]
    assert parent.incomplete and not parent.moved


def test_survey_does_not_ask_for_a_count_when_a_direct_pin_is_current():
    asked = []

    findings = pins.survey(
        [_pin()],
        fetch=lambda repo: PINNED,
        ahead=lambda *args: asked.append(args),
        upstream=lambda repo: None,
    )
    assert asked == []
    assert findings[0].upstream_ahead is None
    assert not findings[0].moved


# ── the report ──────────────────────────────────────────────────────────────


def test_render_says_moved_and_current_and_omits_a_count_that_does_not_apply():
    findings = [
        pins.Finding(_pin(), MOVED_TO, 161, "direct"),
        pins.Finding(_pin("o/s"), PINNED, None, "direct"),
    ]
    report = pins.render(findings)
    assert "MOVED" in report
    assert "161" in report
    assert "| — |" in report
    assert "1 of 2 pins moved upstream" in report


def test_render_flags_a_repository_it_could_not_read():
    report = pins.render([pins.Finding(_pin(), None, None, "direct", incomplete=True)])
    assert "incomplete" in report
    assert "check is incomplete" in report


def test_render_lists_unparseable_declarations():
    report = pins.render([], [pins.Problem("Dockerfile.x", "SOCIALOSINT_REF=main")])
    assert "unparseable" in report
    assert "SOCIALOSINT_REF=main" in report


# ── exit codes the workflow keys off ────────────────────────────────────────


def test_main_exits_2_when_no_pin_is_found(tmp_path, capsys):
    assert pins.main(["--root", str(tmp_path)]) == 2
    assert "pin format changed" in capsys.readouterr().err


def test_main_exits_2_on_an_unparseable_declaration(tmp_path, capsys):
    (tmp_path / "Dockerfile.thing").write_text(
        "# Source: https://github.com/o/r (MIT)\nARG THING_REF=main\n",
        encoding="utf-8",
    )
    assert pins.main(["--root", str(tmp_path)]) == 2


def test_main_exits_1_on_drift_and_0_when_everything_is_current(monkeypatch):
    monkeypatch.setattr(pins, "collect_pins", lambda root: ([_pin()], []))
    monkeypatch.setattr(
        pins,
        "survey",
        lambda *a, **k: [pins.Finding(_pin(), MOVED_TO, None, "direct")],
    )
    assert pins.main([]) == 1

    monkeypatch.setattr(
        pins,
        "survey",
        lambda *a, **k: [pins.Finding(_pin(), PINNED, None, "direct")],
    )
    assert pins.main([]) == 0


def test_main_exits_2_when_the_check_is_incomplete(monkeypatch):
    monkeypatch.setattr(pins, "collect_pins", lambda root: ([_pin()], []))
    monkeypatch.setattr(
        pins,
        "survey",
        lambda *a, **k: [pins.Finding(_pin(), PINNED, None, "direct", incomplete=True)],
    )
    assert pins.main([]) == 2
