"""
Unit tests for the SpiderFoot collector.

All tests are offline: the SpiderFoot web API is mocked with pytest-httpx using
the response shapes of SpiderFoot 4.0 (sfwebui.py), and the poll sleep is
patched out.
"""

from __future__ import annotations

import re
from unittest.mock import patch

import httpx
import pytest

from orchestrator.collectors import spiderfoot as spiderfoot_module
from orchestrator.collectors.spiderfoot import SpiderFootCollector
from orchestrator.config import settings
from orchestrator.models import Target

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
        ([], "UNKNOWN"),
    ],
)
def test_extract_status(payload, expected):
    assert SpiderFootCollector._extract_status(payload) == expected


def test_default_modules_are_real_spiderfoot4_modules():
    # sfp_dns and sfp_ssl do not exist in SpiderFoot 4; an unknown module makes
    # the scan run nothing.
    from orchestrator.config import Settings  # noqa: PLC0415

    default = Settings.model_fields["spiderfoot_modules"].default
    assert default.split(",") == ["sfp_dnsresolve", "sfp_whois", "sfp_sslcert"]
