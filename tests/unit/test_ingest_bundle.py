"""
``python -m orchestrator.ingest_bundle``: parse an external STIX 2.1 bundle and
hand it to the OpenCTI sink (ADR-011).

The module imports pycti before ``stix2.parse`` on purpose; the fixture carries
a ``bank-account`` and a ``text`` (OpenCTI SCOs) so the test fails if that order
is ever lost. Nothing here touches the network: the sink is faked.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import orchestrator.ingest_bundle as mod

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "external_bundle.stix.json"
FIXTURE_OBJECTS = 4


class _FakeSink:
    """Records the ingest calls instead of contacting OpenCTI."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, str]] = []

    def ingest(
        self, bundle: Any, work_name: str = "osint-orchestrator", *, target_id: str | None = None
    ) -> None:
        self.calls.append((len(bundle.objects), work_name))


def test_load_bundle_parses_opencti_scos() -> None:
    bundle = mod.load_bundle(FIXTURE)
    assert {o.type for o in bundle.objects} == {"identity", "bank-account", "text", "relationship"}


def test_dry_run_does_not_build_the_sink(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom() -> None:  # pragma: no cover - only reached on failure
        raise AssertionError("OpenCTISink must not be built in --dry-run")

    monkeypatch.setattr(mod, "OpenCTISink", boom)
    assert mod.main([str(FIXTURE), "--dry-run"]) == 0
    assert f"{FIXTURE_OBJECTS} objects parsed" in capsys.readouterr().out


def test_main_ingests_through_the_sink(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _FakeSink()
    monkeypatch.setattr(mod, "OpenCTISink", lambda: fake)
    work = "investigation-assistant:demo"
    assert mod.main([str(FIXTURE), "--work-name", work]) == 0
    assert fake.calls == [(FIXTURE_OBJECTS, work)]
    assert f"{FIXTURE_OBJECTS} objects ingested" in capsys.readouterr().out


def test_rejects_a_file_that_is_not_a_bundle(tmp_path: Path) -> None:
    path = tmp_path / "not-a-bundle.json"
    path.write_text(json.dumps({"type": "identity"}), encoding="utf-8")
    assert mod.main([str(path)]) == 2


def test_rejects_a_missing_file(tmp_path: Path) -> None:
    assert mod.main([str(tmp_path / "missing.json")]) == 2


def test_rejects_a_bundle_that_stix2_cannot_parse(tmp_path: Path) -> None:
    # A bundle whose object misses a required property: stix2 raises its own
    # STIXError, which must become exit 2 rather than a traceback.
    path = tmp_path / "broken.json"
    path.write_text(
        json.dumps(
            {
                "type": "bundle",
                "id": "bundle--a1b2c3d4-5678-4abc-8def-0123456789ab",
                "objects": [
                    {
                        "type": "identity",
                        "spec_version": "2.1",
                        "id": "identity--a1b2c3d4-5678-4abc-8def-0123456789ab",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert mod.main([str(path)]) == 2


class _FailingSink:
    """Raises what ``OpenCTISink.ingest`` lets out once retries are spent."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def ingest(self, bundle: Any, work_name: str = "osint-orchestrator", **_: Any) -> None:
        raise self.exc


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(ValueError({"name": "AuthRequired"}), id="authentication"),
        pytest.param(OSError("connection refused"), id="connection"),
    ],
)
def test_a_sink_error_exits_1_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, exc: Exception
) -> None:
    monkeypatch.setattr(mod, "OpenCTISink", lambda: _FailingSink(exc))
    assert mod.main([str(FIXTURE)]) == 1
