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


# ── parsing the pins out of the real files ──────────────────────────────────


def test_collect_pins_finds_the_three_pins_dependabot_cannot_see():
    found = {pin.repo for pin in pins.collect_pins(ROOT)}
    assert found == {
        "careb36/OpenOSINT",
        "smicallef/spiderfoot",
        "bm-github/owasp-social-osint-agent",
    }


def test_collect_pins_returns_full_sixes():
    for pin in pins.collect_pins(ROOT):
        assert len(pin.ref) == 40
        assert pin.ref == pin.ref.lower()


def test_compose_pin_is_attributed_to_its_service_not_to_the_context_key():
    # The first version walked backwards for any line ending in ":" and
    # reported "context", which is the key the URL sits on, not the service.
    spiderfoot = next(pin for pin in pins.collect_pins(ROOT) if pin.repo == "smicallef/spiderfoot")
    assert spiderfoot.detail == "spiderfoot"
    assert spiderfoot.source == "docker-compose.yml"


def test_dockerfile_pin_takes_the_url_above_the_arg(tmp_path):
    (tmp_path / "Dockerfile.thing").write_text(
        "# Source: https://github.com/some-org/some-repo (MIT)\n"
        "FROM python:3.11-slim\n"
        f"ARG THING_REF={PINNED}\n",
        encoding="utf-8",
    )
    found = pins.collect_pins(tmp_path)
    assert [(pin.repo, pin.ref, pin.detail) for pin in found] == [
        ("some-org/some-repo", PINNED, "THING_REF")
    ]


def test_collect_pins_deduplicates_the_same_commit_pinned_twice(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  one:\n"
        f"    build:\n      context: https://github.com/o/r.git#{PINNED}\n"
        "  two:\n"
        f"    build:\n      context: https://github.com/o/r.git#{PINNED}\n",
        encoding="utf-8",
    )
    assert len(pins.collect_pins(tmp_path)) == 1


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


def test_upstream_ahead_is_unknown_rather_than_wrong_on_a_failed_call():
    def run(command):
        raise subprocess.CalledProcessError(1, command)

    assert pins.count_upstream_ahead("o/r", PINNED, MOVED_TO, run=run) is None


# ── the report ──────────────────────────────────────────────────────────────


def test_survey_reports_the_fork_parent_separately_from_the_fork():
    def fetch(repo):
        return PINNED if repo == "careb36/OpenOSINT" else MOVED_TO

    findings = pins.survey(
        [pins.Pin("careb36/OpenOSINT", PINNED, "pyproject.toml", "PEP 508 direct reference")],
        fetch=fetch,
        ahead=lambda *_: 161,
        upstream=lambda repo: "OpenOSINT/OpenOSINT",
    )
    fork, parent = findings
    assert fork.pin.repo == "careb36/OpenOSINT"
    assert not fork.moved
    assert parent.pin.repo == "OpenOSINT/OpenOSINT"
    assert parent.moved
    assert parent.upstream_ahead == 161


def test_survey_does_not_ask_for_a_count_when_the_pin_is_current():
    asked = []

    findings = pins.survey(
        [pins.Pin("o/r", PINNED, "pyproject.toml", "x")],
        fetch=lambda repo: PINNED,
        ahead=lambda *args: asked.append(args),
        upstream=lambda repo: None,
    )
    assert asked == []
    assert findings[0].upstream_ahead is None


def test_render_says_moved_and_current_and_omits_a_count_that_does_not_apply():
    findings = [
        pins.Finding(pins.Pin("o/r", PINNED, "pyproject.toml", "x"), MOVED_TO, 161),
        pins.Finding(pins.Pin("o/s", PINNED, "Dockerfile.x", "ARG"), PINNED, None),
    ]
    report = pins.render(findings)
    assert "MOVED" in report
    assert "161" in report
    assert "| — |" in report
    assert "1 of 2 pinned commits moved upstream" in report


def test_render_flags_a_repository_it_could_not_read():
    report = pins.render([pins.Finding(pins.Pin("o/r", PINNED, "x", "y"), None, None)])
    assert "unreadable" in report
    assert "check is incomplete" in report


# ── exit codes the workflow keys off ────────────────────────────────────────


def test_main_exits_2_when_no_pin_is_found(tmp_path, capsys):
    assert pins.main(["--root", str(tmp_path)]) == 2
    assert "pin format changed" in capsys.readouterr().err


def test_main_exits_1_on_drift_and_0_when_everything_is_current(monkeypatch, capsys):
    monkeypatch.setattr(pins, "collect_pins", lambda root: [pins.Pin("o/r", PINNED, "x", "y")])
    monkeypatch.setattr(
        pins,
        "survey",
        lambda *a, **k: [pins.Finding(pins.Pin("o/r", PINNED, "x", "y"), MOVED_TO, None)],
    )
    assert pins.main([]) == 1

    monkeypatch.setattr(
        pins,
        "survey",
        lambda *a, **k: [pins.Finding(pins.Pin("o/r", PINNED, "x", "y"), PINNED, None)],
    )
    assert pins.main([]) == 0


@pytest.mark.parametrize("flag", ["--no-behind"])
def test_main_accepts_its_documented_flags(monkeypatch, flag):
    monkeypatch.setattr(pins, "collect_pins", lambda root: [pins.Pin("o/r", PINNED, "x", "y")])
    monkeypatch.setattr(
        pins,
        "survey",
        lambda *a, **k: [pins.Finding(pins.Pin("o/r", PINNED, "x", "y"), PINNED, None)],
    )
    assert pins.main([flag]) == 0
