"""Operator timestamps: local date and time with the UTC instant beside it."""

from __future__ import annotations

import tomllib
from datetime import UTC, datetime
from pathlib import Path

import pytest

import orchestrator
from orchestrator.timefmt import local_stamp

INSTANT = datetime(2026, 10, 25, 3, 20, 6, tzinfo=UTC)


def test_local_stamp_spanish_and_english(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("orchestrator.timefmt.settings.orchestrator_timezone", "America/Montevideo")
    assert local_stamp(INSTANT, "es") == "25/10/2026 00:20 -03 (2026-10-25T03:20:06Z)"
    assert local_stamp(INSTANT, "en", code=True) == "2026-10-25 00:20 -03 (`2026-10-25T03:20:06Z`)"


def test_naive_is_utc_none_is_dash_and_blank_or_bad_zone_is_utc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for zone in ("", "   ", "Mars/Olympus"):
        monkeypatch.setattr("orchestrator.timefmt.settings.orchestrator_timezone", zone)
        assert local_stamp(INSTANT.replace(tzinfo=None), "es") == (
            "25/10/2026 03:20 UTC (2026-10-25T03:20:06Z)"
        )
    assert local_stamp(None, "es") == "-"


def test_package_version_matches_pyproject() -> None:
    """orchestrator.__version__ is printed in every report; keep it honest."""
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    assert orchestrator.__version__ == tomllib.loads(pyproject.read_text())["project"]["version"]
