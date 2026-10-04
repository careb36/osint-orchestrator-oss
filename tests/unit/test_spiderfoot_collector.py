"""
Unit tests for the SpiderFoot collector.

All tests are offline: the SpiderFoot web API is mocked with pytest-httpx using
the response shapes of SpiderFoot 4.0 (sfwebui.py), and the poll sleep is
patched out.
"""

from __future__ import annotations

import logging
import pathlib
import re
from unittest.mock import patch

import httpx
import pytest
import yaml

from orchestrator.collectors import spiderfoot as spiderfoot_module
from orchestrator.collectors.spiderfoot import SpiderFootCollector
from orchestrator.config import settings
from orchestrator.models import Target

REPO_ROOT = pathlib.Path(__file__).parents[2]
BASE_URL = "http://spiderfoot.test:5001"
SCAN_ID = "D90E1172"


def _row(data: str, event_type: str, source: str = "example.com") -> list:
    """One /scaneventresults row as SpiderFoot 4 renders it (type last)."""
    return [
        "2026-10-04 13:26:05",
        data,
        source,
        "sfp_dnsresolve",
        100,
        100,
        0,
        "2795da9d687c0a65",
        0,
        0,
        event_type,
    ]


def _status(status: str) -> list:
    return [
        "orchestrator-example.com",
        "example.com",
        "2026-10-04 13:26:05",
        "2026-10-04 13:26:05",
        "2026-10-04 13:26:06",
        status,
        {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    ]


@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    monkeypatch.setattr(settings, "spiderfoot_url", BASE_URL)
    monkeypatch.setattr(settings, "spiderfoot_modules", "sfp_dnsresolve")


@pytest.fixture(autouse=True)
def _no_sleep():
    async def _instant(_delay):
        return None

    with patch.object(spiderfoot_module.asyncio, "sleep", _instant):
        yield


def _collector() -> SpiderFootCollector:
    return SpiderFootCollector(
        Target(id="t1", fqdn="example.com", authorization="self-owned", purpose="test")
    )


async def test_full_scan_maps_spiderfoot4_rows(httpx_mock):
    httpx_mock.add_response(method="POST", url=f"{BASE_URL}/startscan", json=["SUCCESS", SCAN_ID])
    httpx_mock.add_response(
        method="GET",
        url=re.compile(rf"{BASE_URL}/scanstatus\?id={SCAN_ID}"),
        json=_status("FINISHED"),
    )
    httpx_mock.add_response(
        method="GET",
        url=re.compile(rf"{BASE_URL}/scaneventresults\?id={SCAN_ID}"),
        json=[
            _row("104.20.23.154", "IP_ADDRESS"),
            _row("example.com", "DOMAIN_NAME"),
            _row("a&amp;b@example.com", "EMAILADDR"),
            _row("ignored", "RAW_DNS_RECORDS"),
        ],
    )

    result = await _collector().collect()

    assert result.success, result.error
    values = {(o.type, o.value) for o in result.observables}
    assert ("ipv4-addr", "104.20.23.154") in values
    # The data column is HTML-escaped by SpiderFoot and must be unescaped.
    assert ("email-addr", "a&b@example.com") in values
    assert not any(o.value == "ignored" for o in result.observables)
    assert [(r.target_value, r.relationship_type) for r in result.relationships] == [
        ("104.20.23.154", "resolves-to")
    ]


async def test_startscan_requests_json_and_reads_id(httpx_mock):
    httpx_mock.add_response(method="POST", url=f"{BASE_URL}/startscan", json=["SUCCESS", SCAN_ID])
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        scan_id = await _collector()._start_scan(client, "example.com")

    assert scan_id == SCAN_ID
    request = httpx_mock.get_request()
    assert "application/json" in request.headers["Accept"]


async def test_startscan_error_reply_fails_the_collector(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE_URL}/startscan",
        json=["ERROR", "Incorrect usage: no modules specified for scan."],
    )

    result = await _collector().collect()

    assert not result.success
    assert "no modules specified" in (result.error or "")


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (_status("RUNNING"), "RUNNING"),
        (_status("FINISHED"), "FINISHED"),
        ({"status": "ERROR-FAILED"}, "ERROR-FAILED"),
        # A build that wraps the row in a list of rows.
        ([_status("FINISHED")], "FINISHED"),
        ([], "UNKNOWN"),
    ],
)
def test_extract_status(payload, expected):
    assert SpiderFootCollector._extract_status(payload) == expected


def test_parse_survives_a_different_row_arity():
    collector = _collector()
    # One extra trailing column: the type is no longer last but still present.
    wider = [*_row("104.20.23.154", "IP_ADDRESS"), 0]
    # One column fewer, type still last.
    narrower = _row("example.org", "INTERNET_NAME")[:4] + ["INTERNET_NAME"]

    result = collector._parse([wider, narrower], "example.com")

    values = {(o.type, o.value) for o in result.observables}
    assert ("ipv4-addr", "104.20.23.154") in values
    assert ("domain-name", "example.org") in values


def test_parse_logs_rows_with_an_unrecognised_layout(caplog):
    unknown = ["2026-10-04 13:26:05", "104.20.23.154", "example.com", 0]

    with caplog.at_level(logging.WARNING, logger=spiderfoot_module.__name__):
        result = _collector()._parse(
            [unknown, "not-a-row", {"data": "104.20.23.154"}], "example.com"
        )

    assert [o.value for o in result.observables] == ["example.com"]
    assert "3 of 3 result rows had an unrecognised layout" in caplog.text


def test_mapped_type_wins_over_an_uppercase_trailing_column():
    # A trailing upper-case token that is not an event type (e.g. a risk label)
    # must not hide the real type earlier in the row.
    row = [*_row("104.20.23.154", "IP_ADDRESS"), "HIGH"]

    result = _collector()._parse([row], "example.com")

    assert ("ipv4-addr", "104.20.23.154") in {(o.type, o.value) for o in result.observables}


def _env_example_value(key: str) -> str:
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    match = re.search(rf"(?m)^{key}=(\S*)", text)
    assert match, f"{key} missing from .env.example"
    return match.group(1)


def test_default_modules_are_in_sync_across_config_env_and_helm():
    from orchestrator.config import Settings  # noqa: PLC0415

    default = Settings.model_fields["spiderfoot_modules"].default
    values = yaml.safe_load(
        (REPO_ROOT / "deploy/helm/osint-orchestrator/values.yaml").read_text(encoding="utf-8")
    )

    assert _env_example_value("SPIDERFOOT_MODULES") == default
    assert values["config"]["spiderfootModules"] == default


def test_default_modules_do_not_use_names_missing_from_spiderfoot4():
    # Checked against the module list of the SpiderFoot 4 image on 2026-10-04:
    # sfp_dns and sfp_ssl do not exist, and an unknown module makes the scan
    # run nothing. This catches a revert, not an upstream rename.
    from orchestrator.config import Settings  # noqa: PLC0415

    modules = Settings.model_fields["spiderfoot_modules"].default.split(",")
    assert not {"sfp_dns", "sfp_ssl"} & set(modules)
