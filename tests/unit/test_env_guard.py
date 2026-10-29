"""The scrub must not take away the environment the integration suite needs.

tests/integration/test_e2e.py reads ORCHESTRATOR_URL and ORCHESTRATOR_API_KEY
from the process environment at import time. Scrubbing unconditionally made
`pytest -m integration` test localhost defaults with an empty key instead of the
stack it was pointed at — the review on #181 caught it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.env_guard import SETTINGS_PREFIXES, keeps_environment, scrub

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("argv", "keeps"),
    [
        # CI's selection: hermetic, so the developer's .env must not leak in.
        (["tests/unit/", "-m", "not integration"], False),
        (["tests/unit/"], False),
        (["tests/unit/test_alerts.py", "-m", "not integration"], False),
        # Anything that can reach the integration module keeps the environment.
        (["-m", "integration"], True),
        (["-m", "integration or unit"], True),
        (["--markexpr=integration"], True),
        (["tests/integration"], True),
        (["tests/integration/test_e2e.py"], True),
        # A path that contains the integration directory can reach it.
        (["tests"], True),
        ([], True),  # testpaths = ["tests"], so a bare pytest collects everything
    ],
)
def test_keeps_environment(argv: list[str], keeps: bool) -> None:
    assert keeps_environment(argv, REPO_ROOT) is keeps


def test_option_values_are_not_mistaken_for_paths() -> None:
    # `-m integration` is an expression; `integration` must not be read as a path.
    assert keeps_environment(["-m", "integration"], REPO_ROOT)
    assert not keeps_environment(["-k", "not_integration", "tests/unit"], REPO_ROOT)


def test_scrub_removes_only_settings_variables() -> None:
    environ = {
        "ORCHESTRATOR_API_KEY": "x",
        "OPENCTI_ENABLED": "true",
        "TAVILY_API_KEY": "y",
        "PATH": "/usr/bin",
        "HOME": "/home/x",
        "OPENCTI": "no underscore, so not a prefixed setting",
    }

    removed = scrub(environ)

    assert sorted(removed) == ["OPENCTI_ENABLED", "ORCHESTRATOR_API_KEY", "TAVILY_API_KEY"]
    assert set(environ) == {"PATH", "HOME", "OPENCTI"}


def test_every_prefix_is_upper_case_and_specific() -> None:
    """A one-letter prefix would delete unrelated variables from the environment."""
    assert all(prefix.isupper() and "_" not in prefix for prefix in SETTINGS_PREFIXES)
    assert all(len(prefix) >= 3 for prefix in SETTINGS_PREFIXES)
