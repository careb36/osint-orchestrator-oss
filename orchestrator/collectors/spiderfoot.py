"""
SpiderFoot collector.

SpiderFoot exposes a CherryPy web UI + unofficial REST endpoints at port 5001.
There is NO versioned /api/v1/ prefix — all endpoints are at root path.

Key endpoints used (shapes checked against SpiderFoot 4.0 sfwebui.py):
  POST /startscan   → with ``Accept: application/json``: ["SUCCESS", "<scan id>"]
                      or ["ERROR", "<message>"]; without that header it
                      answers 303 to the HTML scan page
  GET  /scanstatus?id=<id>  → [name, target, created, started, ended, status, risk]
  GET  /scaneventresults?id=<id>&eventType=  → rows of
                      [last_seen, data, source_data, module, ..., event_type]
                      with data/source HTML-escaped and the type last
  GET  /ping        → health check

Reference: smicallef/spiderfoot:sfwebui.py (port 5001, @cherrypy.expose methods)
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
import logging
import re
import uuid
from datetime import UTC, datetime

import httpx

from orchestrator.collectors import BaseCollector
from orchestrator.config import settings
from orchestrator.models import (
    CollectorName,
    CollectorResult,
    Observable,
    Relationship,
    Target,
)

logger = logging.getLogger(__name__)

# SpiderFoot event types → STIX observable type
_SF_EVENT_TO_STIX: dict[str, str] = {
    "IP_ADDRESS": "ipv4-addr",
    "IPV6_ADDRESS": "ipv6-addr",
    "INTERNET_NAME": "domain-name",
    "DOMAIN_NAME": "domain-name",
    "DOMAIN_NAME_PARENT": "domain-name",
    "URL_ADVERT": "url",
    "EMAILADDR": "email-addr",
    "EMAILADDR_COMPROMISED": "email-addr",
    "URL_STATIC": "url",
    "URL_DYNAMIC": "url",
    "SSL_CERTIFICATE_ISSUED": "x509-certificate",
    # NETBLOCK*_OWNER carry a CIDR block (sfp_ripe and others), which STIX
    # ipv4-addr / ipv6-addr values allow; BGP_AS_* carry the AS number.
    "NETBLOCK_OWNER": "ipv4-addr",
    "NETBLOCKV6_OWNER": "ipv6-addr",
    "BGP_AS_OWNER": "autonomous-system",
    "BGP_AS_MEMBER": "autonomous-system",
}

# STIX 2.1 autonomous-system.number is a 32-bit unsigned integer.
_MAX_ASN = 2**32 - 1

# SpiderFoot event type names: upper-case tokens such as IP_ADDRESS.
_SF_EVENT_TYPE_RE = re.compile(r"[A-Z][A-Z0-9_]*")

# Which SF event types create a "resolves-to" relationship with the target domain
_RESOLVES_FROM_DOMAIN = {"IP_ADDRESS", "IPV6_ADDRESS", "INTERNET_NAME"}


class SpiderFootCollector(BaseCollector):
    """HTTP collector driving a running SpiderFoot service (start → poll → parse).

    This is the only collector performing live DNS/TLS/HTTP probing of the
    target — see the Authorised-use policy. Modules come from the target
    config, falling back to ``SPIDERFOOT_MODULES``; the whole scan is bounded
    by ``timeout_seconds``.
    """

    name = CollectorName.SPIDERFOOT

    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self._base_url = settings.spiderfoot_url
        cfg = target.collectors.spiderfoot
        self._timeout = cfg.timeout_seconds
        self._modules = cfg.modules or settings.spiderfoot_modules.split(",")

    async def collect(self) -> CollectorResult:
        """Start a scan, wait for completion and map raw events to observables.

        Never raises: any failure (service down, timeout, parse error) returns
        ``success=False`` so one collector cannot take the run down.
        """
        fqdn = self.target.fqdn
        logger.info("SpiderFoot: starting scan for %s", fqdn)

        async with httpx.AsyncClient(base_url=self._base_url, timeout=30) as client:
            try:
                scan_id = await self._start_scan(client, fqdn)
                logger.info("SpiderFoot scan %s started for %s", scan_id, fqdn)
                try:
                    await self._wait_for_scan(client, scan_id)
                    raw_events = await self._fetch_results(client, scan_id)
                except BaseException:
                    # A scan this run gave up on (timeout, cancellation, a
                    # polling error) keeps probing the target on the SpiderFoot
                    # side until someone stops it, and every scheduled run
                    # would add another. Best effort: the original error wins.
                    await self._stop_scan(client, scan_id)
                    raise
                return self._parse(raw_events, fqdn)
            except Exception as exc:  # noqa: BLE001
                logger.error("SpiderFoot failed for %s: %s", fqdn, exc)
                return CollectorResult(
                    collector=self.name,
                    target_fqdn=fqdn,
                    success=False,
                    error=str(exc),
                )

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _start_scan(self, client: httpx.AsyncClient, fqdn: str) -> str:
        """POST /startscan and return the scan ID."""
        scan_name = f"orchestrator-{fqdn}-{uuid.uuid4().hex[:8]}"
        modules = ",".join(self._modules)

        resp = await client.post(
            "/startscan",
            # Without this header SpiderFoot answers 303 to the HTML scan page.
            headers={"Accept": "application/json"},
            data={
                "scanname": scan_name,
                "scantarget": fqdn,
                "modulelist": modules,
                "typelist": "",
                "usecase": "all",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        # SpiderFoot 4 returns ["SUCCESS", "<id>"] or ["ERROR", "<message>"];
        # a dict with an id is accepted for other builds.
        if isinstance(data, dict):
            scan_id = data.get("id") or data.get("scanId") or data.get("scan_id")
            if scan_id:
                return str(scan_id)
        if isinstance(data, list) and len(data) >= 2:
            if data[0] == "SUCCESS" and data[1]:
                return str(data[1])
            if data[0] == "ERROR":
                raise RuntimeError(f"SpiderFoot refused the scan: {data[1]}")
        raise ValueError(f"Unexpected /startscan response: {data}")

    async def _wait_for_scan(self, client: httpx.AsyncClient, scan_id: str) -> None:
        """Poll /scanstatus until FINISHED, ERROR, or timeout."""
        deadline = asyncio.get_event_loop().time() + self._timeout
        poll_interval = 10

        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(poll_interval)
            resp = await client.get("/scanstatus", params={"id": scan_id})
            resp.raise_for_status()
            data = resp.json()
            # /scanstatus returns [name, target, created, started, ended, status, risk]
            # (or a dict on other builds)
            status = self._extract_status(data)
            logger.debug("SpiderFoot scan %s status: %s", scan_id, status)
            if status in ("FINISHED", "ABORT-REQUESTED", "ABORTED"):
                return
            if status == "ERROR-FAILED":
                raise RuntimeError(f"SpiderFoot scan {scan_id} failed with ERROR-FAILED")

        raise TimeoutError(f"SpiderFoot scan {scan_id} did not finish within {self._timeout}s")

    @staticmethod
    def _extract_status(data: list | dict) -> str:
        """Normalise the scan status out of SpiderFoot's dict-or-rows response."""
        if isinstance(data, dict):
            return data.get("status", "UNKNOWN")
        # Some builds wrap the row in a list of rows; read the first one.
        if isinstance(data, list) and data and isinstance(data[0], list):
            data = data[0]
        if isinstance(data, list) and len(data) >= 6 and isinstance(data[5], str):
            return data[5]
        return "UNKNOWN"

    @staticmethod
    def _read_event_data(stix_type: str, raw: object) -> str | None:
        """The observable value of an event, or None when it is unusable.

        One policy for both row layouts: strings are HTML-unescaped (SpiderFoot
        escapes the data column); AS numbers must be 1..2**32-1, given as an
        int or as "13335"/"AS13335"; IP values must parse as an address or a
        CIDR block of the right family. Anything else (None, bool, float, a
        container, "0", "n/a") is rejected rather than becoming a bogus
        observable such as AS0.
        """
        if isinstance(raw, bool):
            return None
        if stix_type == "autonomous-system":
            if isinstance(raw, int):
                number = raw
            elif isinstance(raw, str):
                digits = html.unescape(raw).strip().upper().removeprefix("AS")
                # isascii: str.isdigit() accepts digits int() rejects (e.g. "²").
                if not (digits.isascii() and digits.isdigit()):
                    return None
                number = int(digits)
            else:
                return None
            return str(number) if 0 < number <= _MAX_ASN else None
        if not isinstance(raw, str):
            return None
        value = html.unescape(raw).strip()
        if stix_type in ("ipv4-addr", "ipv6-addr"):
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                return None
            if network.version != (4 if stix_type == "ipv4-addr" else 6):
                return None
            # Canonical form: STIX wants prefix notation, and ip_network also
            # accepts a netmask ("104.16.0.0/255.248.0.0").
            value = str(network) if "/" in value else str(network.network_address)
        return value or None

    @staticmethod
    def _row_event_type(row: list) -> str | None:
        """Event type of a /scaneventresults row, or None for an unknown layout.

        A column (other than the data one) holding a mapped event type wins,
        wherever it sits, so an extra trailing column cannot hide the type.
        Otherwise SpiderFoot 4's last column is taken when it looks like an
        event type (an unmapped one, which the caller skips as usual).
        """
        for index, value in enumerate(row):
            if index != 1 and isinstance(value, str) and value in _SF_EVENT_TO_STIX:
                return value
        last = row[-1]
        if isinstance(last, str) and _SF_EVENT_TYPE_RE.fullmatch(last):
            return last
        return None

    async def _stop_scan(self, client: httpx.AsyncClient, scan_id: str) -> None:
        """POST /stopscan for a scan this run will not wait for. Never raises."""
        try:
            resp = await client.post(
                "/stopscan", headers={"Accept": "application/json"}, data={"id": scan_id}
            )
            resp.raise_for_status()
            logger.info("SpiderFoot scan %s stop requested", scan_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("SpiderFoot scan %s could not be stopped: %s", scan_id, exc)

    async def _fetch_results(self, client: httpx.AsyncClient, scan_id: str) -> list[dict]:
        """GET /scaneventresults and return list of event rows."""
        resp = await client.get(
            "/scaneventresults",
            params={"id": scan_id, "eventType": ""},
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        return []

    def _parse(self, events: list[dict | list], fqdn: str) -> CollectorResult:
        """
        Convert SpiderFoot event rows to CollectorResult.

        SpiderFoot 4 /scaneventresults returns rows like:
          [last_seen, data, source_data, module, confidence, visibility, risk,
           hash, false_positive, ..., event_type]
        with ``data`` HTML-escaped and the event type in the last column, or
        dicts with "type", "data", etc. on other builds.
        """
        observables: list[Observable] = []
        relationships: list[Relationship] = []
        seen_values: set[str] = set()

        # Always include the root target
        observables.append(Observable(type="domain-name", value=fqdn))
        seen_values.add(fqdn)

        unreadable = 0
        for event in events:
            if isinstance(event, list) and len(event) >= 2:
                event_type = self._row_event_type(event)
                raw_data = event[1]
            elif isinstance(event, dict):
                # A non-string type would be an unhashable map key.
                event_type = event.get("type")
                if not isinstance(event_type, str) or not event_type:
                    event_type = None
                raw_data = event.get("data")
            else:
                event_type, raw_data = None, None
            if event_type is None:
                unreadable += 1
                continue

            stix_type = _SF_EVENT_TO_STIX.get(event_type)
            if stix_type is None:
                continue  # an event type we do not map: normal filtering

            data = self._read_event_data(stix_type, raw_data)
            if data is None:
                unreadable += 1
                continue
            if data in seen_values:
                continue

            seen_values.add(data)
            observables.append(
                Observable(type=stix_type, value=data, extra={"sf_event": event_type})
            )
            if event_type in _RESOLVES_FROM_DOMAIN:
                relationships.append(
                    Relationship(
                        source_value=fqdn,
                        source_type="domain-name",
                        target_value=data,
                        target_type=stix_type,
                        relationship_type="resolves-to",
                    )
                )

        if unreadable:
            # A layout change would otherwise look like a clean scan that found
            # nothing but the root domain.
            logger.warning(
                "SpiderFoot: %d of %d result rows were unreadable "
                "(unknown layout or unusable value) for %s",
                unreadable,
                len(events),
                fqdn,
                extra={
                    "target_id": self.target.id,
                    "collector": self.name.value,
                    "skipped_rows": unreadable,
                },
            )

        return CollectorResult(
            collector=self.name,
            target_fqdn=fqdn,
            collected_at=datetime.now(UTC),
            observables=observables,
            relationships=relationships,
            success=True,
        )
